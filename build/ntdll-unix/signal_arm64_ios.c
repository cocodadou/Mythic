/*
 * ARM64 signal handling routines
 *
 * Copyright 2010-2013 André Hentschel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#ifdef __aarch64__

#include "config.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#ifdef WINE_IOS
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <pthread/pthread.h>
#include <pthread/qos.h>
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYSCALL_H
# include <syscall.h>
#else
# ifdef HAVE_SYS_SYSCALL_H
#  include <sys/syscall.h>
# endif
#endif
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#ifdef HAVE_SYS_UCONTEXT_H
# include <sys/ucontext.h>
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/asm.h"
#include "unix_private.h"
#include "wine/debug.h"

/* defined at the bottom of this file with the [thread-stacks] dumper */
static const char *ios_pe_module_name( uint64_t base );

WINE_DEFAULT_DEBUG_CHANNEL(seh);

/* X3 mixed-mode: user-mode entry points follow the current pseudo-process's
 * ntdll image (cross-arch children run a private ARM64EC ntdll). Falls back
 * to the session p* globals when the process has no private image. */
#include "ios_mixed.h"
#define IOS_PFUNC(name) __extension__ ({ \
    const struct ios_ntdll_funcs *_iosf = ios_cur_ntdll_funcs(); \
    _iosf ? _iosf->name : (void *)p##name; })

#define NTDLL_DWARF_H_NO_UNWINDER
#include "dwarf.h"

/* ml255: storm gate -- see ios_storm_gate in virtual_ios.c for the rationale
 * (510 MB log from a 524k-iteration NULL-deref loop). */
static int ios_sig_storm_gate( unsigned long *n )
{
    unsigned long c = ++(*n);
    if (c <= 20) return 1;
    if (c <= 100000) return (c % 1000) == 0;
    return (c % 100000) == 0;
}

/***********************************************************************
 * signal context platform-specific definitions
 */
#ifdef linux

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext.reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext.regs[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(pstate, context) /* Current State Register */
# define FP_sig(context)            REGn_sig(29, context)    /* Frame pointer */
# define LR_sig(context)            REGn_sig(30, context)    /* Link Register */

static struct _aarch64_ctx *get_extended_sigcontext( const ucontext_t *sigcontext, unsigned int magic )
{
    struct _aarch64_ctx *ctx = (struct _aarch64_ctx *)sigcontext->uc_mcontext.__reserved;
    while ((char *)ctx < (char *)(&sigcontext->uc_mcontext + 1) && ctx->magic && ctx->size)
    {
        if (ctx->magic == magic) return ctx;
        ctx = (struct _aarch64_ctx *)((char *)ctx + ctx->size);
    }
    return NULL;
}

static struct fpsimd_context *get_fpsimd_context( const ucontext_t *sigcontext )
{
    return (struct fpsimd_context *)get_extended_sigcontext( sigcontext, FPSIMD_MAGIC );
}

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    struct esr_context *esr = (struct esr_context *)get_extended_sigcontext( sigcontext, ESR_MAGIC );
    if (esr) return esr->esr;
    return 0;
}

#elif defined(__APPLE__)

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext->__ss.__ ## reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext->__ss.__x[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(cpsr, context)  /* Current State Register */
# define FP_sig(context)            REG_sig(fp, context)    /* Frame pointer */
# define LR_sig(context)            REG_sig(lr, context)    /* Link Register */

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    return sigcontext->uc_mcontext->__es.__esr;
}

#endif /* linux */

/* stack layout when calling KiUserExceptionDispatcher */
struct exc_stack_layout
{
    CONTEXT              context;        /* 000 */
    CONTEXT_EX           context_ex;     /* 390 */
    EXCEPTION_RECORD     rec;            /* 3b0 */
    ULONG64              align;          /* 448 */
    ULONG64              redzone[2];     /* 450 */
};
C_ASSERT( offsetof(struct exc_stack_layout, rec) == 0x3b0 );
C_ASSERT( sizeof(struct exc_stack_layout) == 0x460 );

/* stack layout when calling KiUserApcDispatcher */
struct apc_stack_layout
{
    void                *func;           /* 000 APC to call*/
    ULONG64              args[3];        /* 008 function arguments */
    ULONG64              alertable;      /* 020 */
    ULONG64              align;          /* 028 */
    CONTEXT              context;        /* 030 */
    ULONG64              redzone[2];     /* 3c0 */
};
C_ASSERT( offsetof(struct apc_stack_layout, context) == 0x30 );
C_ASSERT( sizeof(struct apc_stack_layout) == 0x3d0 );

/* stack layout when calling KiUserCallbackDispatcher */
struct callback_stack_layout
{
    void                *args;           /* 000 arguments */
    ULONG                len;            /* 008 arguments len */
    ULONG                id;             /* 00c function id */
    ULONG64              unknown;        /* 010 */
    ULONG64              lr;             /* 018 */
    ULONG64              sp;             /* 020 sp+pc (machine frame) */
    ULONG64              pc;             /* 028 */
    BYTE                 args_data[0];   /* 030 copied argument data*/
};
C_ASSERT( offsetof(struct callback_stack_layout, sp) == 0x20 );
C_ASSERT( sizeof(struct callback_stack_layout) == 0x30 );

struct syscall_frame
{
    ULONG64               x[29];          /* 000 */
    ULONG64               fp;             /* 0e8 */
    ULONG64               lr;             /* 0f0 */
    ULONG64               sp;             /* 0f8 */
    ULONG64               pc;             /* 100 */
    ULONG                 cpsr;           /* 108 */
    ULONG                 restore_flags;  /* 10c */
    struct syscall_frame *prev_frame;     /* 110 */
    void                 *syscall_cfa;    /* 118 */
    ULONG                 syscall_id;     /* 120 */
    ULONG                 align;          /* 124 */
    ULONG                 fpcr;           /* 128 */
    ULONG                 fpsr;           /* 12c */
    NEON128               v[32];          /* 130 */
};

C_ASSERT( sizeof( struct syscall_frame ) == 0x330 );

#ifdef WINE_IOS
/* Written by __wine_syscall_dispatcher at entry to capture the actual x18 value.
 * Read by the watchdog to verify whether x18 is TEB or 0. */
volatile uint64_t g_wine_dispatcher_x18 = 0xDEADDEAD;
volatile int ios_signal_total = 0;
volatile int ios_signal_last = 0;
volatile int ios_signal_in_pe = 0;  /* signals while PC was in JIT pool */
/* Counter of how many times the dispatcher has been called */
volatile uint64_t g_wine_dispatcher_count = 0;
/* g_wine_unix_call_count is now in loader_ios.c (wrapper table) */
/* Written by __wine_syscall_dispatcher_return to capture frame->x[18] and frame->pc
 * BEFORE they are loaded into registers and we jump to PE code */
volatile uint64_t g_wine_return_x18 = 0xDEADDEAD;
volatile uint64_t g_wine_return_pc = 0xDEADDEAD;
volatile uint64_t g_wine_return_count = 0;
/* Saved right before ret/br to PE code */
volatile uint64_t g_wine_x18_before_ret = 0xDEADDEAD;
volatile uint64_t g_wine_x16_at_ret = 0xDEADDEAD;
/* Ring buffer of last 8 dispatcher_return PCs for crash diagnosis */
#define WINE_RET_RING_SIZE 8
volatile uint64_t g_wine_return_ring[WINE_RET_RING_SIZE];
volatile uint32_t g_wine_return_ring_idx = 0;
/* Counters accessible from BUS handler for crash diagnosis */
volatile int ios_total_segv_count = 0;
/* TEB backup for signal handler x18 restoration */
static __thread uintptr_t ios_teb_for_signals = 0;

/* TLS key for storing TEB, accessible via TPIDRRO_EL0 in patched PE code */
pthread_key_t ios_teb_tls_key = 0;
int ios_teb_tls_slot_offset = 0;  /* byte offset from TPIDRRO_EL0 base to TEB slot */
int ios_teb_tls_key_created = 0;

/*
 * Per-thread Mach exception handler for EXC_BAD_ACCESS.
 * ONE handler thread serves ALL Wine "process" threads.
 * Each Wine thread registers its Mach thread port, TEB, and trampoline
 * in a shared registry. The handler looks up the correct TEB/trampoline
 * for the faulting thread.
 *
 * Handles: x18=0 (TEB corruption), user_shared_data (0x7FFE0000) redirects,
 * and PE→JIT pool execution redirects.
 * Unhandled exceptions fall through to the POSIX SIGSEGV handler.
 */
static mach_port_t ios_exc_port = MACH_PORT_NULL;
static int ios_exc_handler_started = 0;
static uintptr_t ios_exc_usd = 0;
volatile int64_t ios_exc_x18_fixes = 0;
volatile int64_t ios_exc_usd_fixes = 0;
volatile int ios_exc_thread_alive = 0;
volatile int ios_exc_msg_count = 0;
/* Last thread that took an exec fault at a PE VA (i.e. made a native call
 * through the redirect path) — the game thread in practice. The [PROF]
 * sampler in server_ios.c follows this so it profiles the presenting
 * thread instead of whatever thread first hit signal_start_thread (which
 * died ~33s in and left [PROF] sampling a corpse). */
volatile mach_port_t ios_last_exec_fault_thread = MACH_PORT_NULL;

/* Real unix-side KUSER_SHARED_DATA address, for unix code (e.g. win32u's
 * get_tick_count) that would otherwise read the canonical 0x7ffe0000 and
 * eat a Mach fault per load. */
unsigned long long ios_get_real_usd(void)
{
    return (unsigned long long)ios_exc_usd;
}

/* ---- Self-healing stale-pointer patcher ----------------------------------
 * Mechanism-#2 exec faults: pool-resident module copies hold function
 * pointers that still carry PE VAs (lazily-written ARM64EC aux-IAT slots,
 * runtime GetProcAddress results — writes that happen pool-side AFTER the
 * NtProtect sync/translate pass ran). Each call through such a pointer
 * faults (~8K/s in gameplay, each suspending the calling thread for a full
 * handler round trip). The Mach handler enqueues every distinct faulted
 * PE VA here; a low-priority scanner thread rewrites EVERY 8-byte slot in
 * the module-copy pool ranges holding that value to its pool equivalent.
 * Each stale pointer faults once, then never again. FEX CodeBuffer ranges
 * are NOT scanned (guest-RIP constants live there). */
/* 64 → 256 (2026-07-07): with a desktop + several pseudo-processes the
 * boot one-shot VAs alone overflowed 64 slots, and the two-cube DXMT
 * fault storm's VA (child winemetal IAT → child EC ntdll map VA,
 * 315K faults) arrived late and was silently dropped — never tracked,
 * never healed. */
#define IOS_STALE_VA_MAX 256
/* Only heal a VA once it has exec-faulted this many times. Boot-time
 * one-shot redirects (thread entry points, DLL entry calls) fault a
 * handful of times and must NOT be healed — pool slots legitimately hold
 * some of those PE VAs (CONTEXT records, pending thread params), and
 * rewriting them broke boot (2026-07-04 freeze, pre-splash NULL-deref
 * livelock). The pathological stale pointers fault thousands of times per
 * second; a threshold cleanly separates the two populations. */
#define IOS_STALE_VA_HEAL_THRESHOLD 256
static uint64_t ios_stale_va_seen[IOS_STALE_VA_MAX];
static uint32_t ios_stale_va_hits[IOS_STALE_VA_MAX];
static volatile int ios_stale_va_seen_count = 0;
static uint64_t ios_stale_va_queue[IOS_STALE_VA_MAX];
static volatile int ios_stale_va_head = 0;   /* written by scanner */
static volatile int ios_stale_va_tail = 0;   /* written by exc handler */

static void ios_stale_va_enqueue( uint64_t va )
{
    int i, n = ios_stale_va_seen_count;
    for (i = 0; i < n; i++)
    {
        if (ios_stale_va_seen[i] == va)
        {
            if (++ios_stale_va_hits[i] == IOS_STALE_VA_HEAL_THRESHOLD)
            {
                ios_stale_va_queue[ios_stale_va_tail % IOS_STALE_VA_MAX] = va;
                ios_stale_va_tail++;
                fprintf( stderr, "[stale-heal] 0x%llx crossed %d faults — queued for heal\n",
                         (unsigned long long)va, IOS_STALE_VA_HEAL_THRESHOLD );
            }
            return;
        }
    }
    if (n >= IOS_STALE_VA_MAX)
    {
        /* Table full: evict the coldest entry (boot one-shots sit at a
         * handful of hits) so pathological late-comers — a new child's
         * DXMT IAT — still get tracked. Only the single mach-handler
         * thread calls this, so the read-modify-write is safe. */
        int min_i = 0;
        uint32_t min_h = ios_stale_va_hits[0];
        for (i = 1; i < n; i++)
            if (ios_stale_va_hits[i] < min_h) { min_h = ios_stale_va_hits[i]; min_i = i; }
        if (min_h >= IOS_STALE_VA_HEAL_THRESHOLD) return;  /* everything hot — drop */
        ios_stale_va_seen[min_i] = va;
        ios_stale_va_hits[min_i] = 1;
        return;
    }
    ios_stale_va_seen[n] = va;
    ios_stale_va_hits[n] = 1;
    ios_stale_va_seen_count = n + 1;
}

static void *ios_stale_va_scanner( void *arg )
{
    extern int ios_jit_patch_stale_pointer( unsigned long long stale_va );
    /* Healing default-ON since 2026-07-07: the patcher now rewrites ONLY
     * IAT/delay-IAT slots (parsed from each pool copy's PE headers), so
     * the 2026-07-04 breakage class — arm64x metadata slots whose
     * consumers need PE VAs for identity/range comparisons — can't be
     * touched. Import slots hold nothing but call targets; rewriting
     * them is the same transform the NtProtect-time IAT-sync applies.
     * MYTHIC_NO_HEAL=1 reverts to dry-run reporting. */
    int do_heal = getenv( "MYTHIC_NO_HEAL" ) == NULL;
    pthread_setname_np( "wine-stale-heal" );
    for (;;)
    {
        usleep( 100000 );
        while (ios_stale_va_head != ios_stale_va_tail)
        {
            uint64_t va = ios_stale_va_queue[ios_stale_va_head % IOS_STALE_VA_MAX];
            ios_stale_va_head++;
            if (do_heal)
                ios_jit_patch_stale_pointer( va );
            else
                fprintf( stderr, "[stale-heal] (dry-run) hot stale VA 0x%llx — heal skipped (MYTHIC_NO_HEAL set)\n",
                         (unsigned long long)va );
        }
    }
    return NULL;
}

/* Per-thread trampoline for signal handlers (runs on faulting thread) */
static __thread void *ios_my_trampoline = NULL;
static __thread int ios_my_slot = -1;

/* Thread registry: maps Mach thread port → TEB + trampoline */
#define IOS_MAX_WINE_THREADS 64

struct ios_thread_entry {
    thread_t mach_thread;
    uintptr_t teb;
    void *trampoline;
};
static struct ios_thread_entry ios_thread_registry[IOS_MAX_WINE_THREADS];
static volatile int32_t ios_thread_count = 0;

static int ios_lookup_thread(thread_t mach_thread, uintptr_t *teb_out, void **tramp_out)
{
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    for (int i = 0; i < count; i++)
    {
        if (ios_thread_registry[i].mach_thread == mach_thread)
        {
            *teb_out = ios_thread_registry[i].teb;
            *tramp_out = ios_thread_registry[i].trampoline;
            return 1;
        }
    }
    /* Fallback: use first registered thread */
    if (count > 0)
    {
        *teb_out = ios_thread_registry[0].teb;
        *tramp_out = ios_thread_registry[0].trampoline;
        return 1;
    }
    *teb_out = 0;
    *tramp_out = NULL;
    return 0;
}

/* Diagnostic: first .data fault captured by Mach handler */
volatile uint64_t ios_exc_data_fault_pc = 0;
volatile uint64_t ios_exc_data_fault_lr = 0;
volatile uint64_t ios_exc_data_fault_sp = 0;
volatile uint64_t ios_exc_data_fault_frame_ptr = 0;
volatile uint64_t ios_exc_data_fault_frame_pc = 0;
volatile int ios_exc_data_fault_count = 0;
/* Additional register capture for first .data fault */
volatile uint64_t ios_exc_data_x0 = 0;
volatile uint64_t ios_exc_data_x1 = 0;
volatile uint64_t ios_exc_data_x2 = 0;
volatile uint64_t ios_exc_data_x3 = 0;
volatile uint64_t ios_exc_data_x16 = 0;
volatile uint64_t ios_exc_data_x17 = 0;
volatile uint64_t ios_exc_data_x18 = 0;
volatile uint64_t ios_exc_data_x29 = 0;
volatile uint32_t ios_exc_data_insn_at_lr = 0; /* instruction at LR (caller) */

/* Raw Mach exception message structures (64-bit codes) */
#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    int64_t code[2];
} ios_exc_request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret_code;
} ios_exc_reply_t;
#pragma pack()

/* iOS-Mythic ml329 (#53 discriminator): ring of pages the reclaim-recovery path
 * zero-filled. Written by the recovery site, dumped by ios_reclaim_pages_report()
 * from the fatal-SEGV path so "did iOS eat this allocator's memory?" is answered
 * from recorded fact rather than inferred from Wine's vprot (which reads 0 for
 * pages FEX allocated through its own VirtualAlloc2 path, so the existing verdict
 * string says "zeros OK" regardless and cannot settle the question). */
#define IOS_RRPAGE_MAX 128
static volatile unsigned long long ios_rr_pages[IOS_RRPAGE_MAX];
static volatile unsigned ios_rr_pages_n;

void ios_reclaim_note_page( unsigned long long pg );
void ios_reclaim_note_page( unsigned long long pg )
{
    unsigned slot = __sync_fetch_and_add( &ios_rr_pages_n, 1 );
    ios_rr_pages[slot % IOS_RRPAGE_MAX] = pg;
}

void ios_reclaim_pages_report( const char *when, unsigned long long fault_addr );
void ios_reclaim_pages_report( const char *when, unsigned long long fault_addr )
{
    unsigned total = ios_rr_pages_n;
    unsigned shown = total < IOS_RRPAGE_MAX ? total : IOS_RRPAGE_MAX;
    unsigned i, in_fex_band = 0;

    for (i = 0; i < shown; i++)
    {
        unsigned long long pg = ios_rr_pages[i];
        if (pg >= 0x7C00000000ULL && pg < 0x8000000000ULL) in_fex_band++;
    }
    dprintf( STDERR_FILENO,
             "[reclaim-census] rev=ml329 at=%s fault=0x%llx : %u pages zero-filled this run, "
             "%u of the last %u are in FEX's host heap band [0x7c,0x80) -- %s\n",
             when, fault_addr, total, in_fex_band, shown,
             in_fex_band ? "FEX HEAP WAS ZEROED, #53 is live for this crash"
                         : "none in FEX's heap; #53 does NOT explain this crash" );
    for (i = 0; i < shown && i < 16; i++)
        dprintf( STDERR_FILENO, "[reclaim-census]   pg[%u]=0x%llx%s\n", i,
                 (unsigned long long)ios_rr_pages[i],
                 (ios_rr_pages[i] >= 0x7C00000000ULL && ios_rr_pages[i] < 0x8000000000ULL) ? "  <== FEX heap" : "" );
}

static void *ios_mach_exception_thread( void *arg )
{
    mach_port_t port = (mach_port_t)(uintptr_t)arg;

    /* Name this thread for debugging */
    pthread_setname_np("wine-x18-exc");

    /* 2026-07-04 perf: this thread is effectively an interrupt handler —
     * every STR emulation, exec-fault redirect, and USD read (~2,600 per
     * present-group in gameplay) suspends the faulting thread until THIS
     * thread services the message. At default QoS it is E-core-eligible
     * and can be preempted by every USER_INTERACTIVE game thread — each
     * fault then pays scheduling latency on top of handling cost. Run it
     * as hot as its clients. */
    pthread_set_qos_class_self_np( QOS_CLASS_USER_INTERACTIVE, 0 );

    ios_exc_thread_alive = 1;

    for (;;)
    {
        /* Use a large buffer to handle any message variant */
        union {
            ios_exc_request_t typed;
            char buf[1024];
        } msg;
        kern_return_t kr = mach_msg( &msg.typed.head, MACH_RCV_MSG, 0,
                                      sizeof(msg), port,
                                      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL );
        if (kr != KERN_SUCCESS) continue;

        ios_exc_request_t *req = &msg.typed;
        ios_exc_msg_count++;

        thread_t thread = req->thread.name;
        int handled = 0;

        /* 2026-07-03 storm probe: ~40K Mach exceptions PER PRESENT measured
         * in the menu phase (~all of the 1.4s frame time at ~33us each).
         * Sample every 4096th message: exception type + faulting PC + insn
         * so the trap source is nameable from one run. */
        if ((ios_exc_msg_count & 0xFFF) == 0)
        {
            arm_thread_state64_t pstate;
            mach_msg_type_number_t pcount = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state( thread, ARM_THREAD_STATE64,
                                  (thread_state_t)&pstate, &pcount ) == KERN_SUCCESS)
            {
                uint64_t ppc = arm_thread_state64_get_pc( pstate );
                uint32_t pinsn = 0;
                vm_size_t psz = sizeof(pinsn);
                vm_read_overwrite( mach_task_self(), ppc, sizeof(pinsn),
                                   (vm_address_t)&pinsn, &psz );
                dprintf(STDERR_FILENO,
                        "[EXC_SAMPLE] #%d exc=%d code0=0x%llx pc=0x%llx insn=0x%08x lr=0x%llx\n",
                        ios_exc_msg_count, req->exception,
                        (unsigned long long)(req->code_count > 1 ? req->code[1] : req->code[0]),
                        (unsigned long long)ppc, pinsn,
                        (unsigned long long)pstate.__lr);
            }
        }

        /* Look up per-thread TEB and trampoline for the faulting thread */
        uintptr_t thread_teb = 0;
        void *thread_trampoline = NULL;
        ios_lookup_thread( thread, &thread_teb, &thread_trampoline );

        /* Get faulting thread's register state */
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state( thread, ARM_THREAD_STATE64,
                               (thread_state_t)&state, &count );
        /* Also fetch NEON (SIMD/FP) state for STR/STP-q emulation */
        arm_neon_state64_t neon_state;
        mach_msg_type_number_t neon_count = ARM_NEON_STATE64_COUNT;
        int have_neon = (thread_get_state(thread, ARM_NEON_STATE64,
                                          (thread_state_t)&neon_state, &neon_count) == KERN_SUCCESS);
        if (kr == KERN_SUCCESS)
        {
            uintptr_t fault_addr = (uintptr_t)req->code[1];

            /* 1. Redirect user_shared_data accesses (0x7FFE0000) */
            if (fault_addr >= 0x7FFE0000 && fault_addr < 0x7FFF0000 && ios_exc_usd)
            {
                for (int reg = 0; reg <= 28; reg++)
                {
                    if (state.__x[reg] >= 0x7FFE0000 && state.__x[reg] < 0x7FFF0000)
                        state.__x[reg] = ios_exc_usd + (state.__x[reg] - 0x7FFE0000);
                }
                ios_exc_usd_fixes++;
                handled = 1;
            }

            /* 2. Redirect execution faults at original PE mappings to JIT pool.
             * The PE-side loader calls DLL entry points at original mapping
             * addresses which aren't executable on iOS. Translate to JIT. */
            {
                extern void *ios_jit_rx_base_global;
                extern size_t ios_jit_pool_size_global;
                extern int ios_jit_addr_is_text(uintptr_t addr);
                extern void *ios_jit_translate_addr_for_owner(void *addr, void *owner_peb);

                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int is_exec_fault = (fault_addr == (uintptr_t)fault_pc);

                if (is_exec_fault && thread_trampoline)
                {
                    uintptr_t jit_rx = (uintptr_t)ios_jit_rx_base_global;
                    size_t jit_sz = ios_jit_pool_size_global;

                    if (fault_pc >= jit_rx && fault_pc < jit_rx + jit_sz)
                    {
                        /* Exec fault IN JIT pool — only fixable if in .text (x18 issue) */
                        if (ios_jit_addr_is_text(fault_pc) && state.__x[18] == 0 && thread_teb)
                        {
                            state.__x[17] = fault_pc;
                            __darwin_arm_thread_state64_set_pc_fptr(state, thread_trampoline);
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                    }
                    else
                    {
                        /* Exec fault OUTSIDE JIT pool RX — try translations.
                         * IMPORTANT: this handler runs on its own thread, so
                         * translation must use the FAULTING thread's process
                         * (its registered TEB->Peb), not ours — a child
                         * thread's ntdll fault must redirect to the child's
                         * copy (S1 pseudo-processes). */
                        void *jit_pc;
                        void *fault_owner_peb = thread_teb ? ((TEB *)thread_teb)->Peb : NULL;
                        ios_last_exec_fault_thread = thread;
                        jit_pc = ios_jit_translate_addr_for_owner((void *)(uintptr_t)fault_pc,
                                                                  fault_owner_peb);
                        /* Module-mapping hit = a stale PE-VA pointer somewhere
                         * in the pool — queue it for the heal scanner so this
                         * address only ever faults once. */
                        if (jit_pc != (void *)(uintptr_t)fault_pc)
                            ios_stale_va_enqueue((uint64_t)fault_pc);
                        /* [xlate-exec] pseudo-process forensics: every
                         * image-VA exec fault is an ownership decision —
                         * log which copy the thread was routed to. A child
                         * thread landing in a session-owned copy (owner=0
                         * while its teb->peb is a child peb) is the
                         * cross-copy migration that kills thread exit. */
                        {
                            extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                            /* Child threads only — the session's own boot
                             * takes thousands of these and drowned the
                             * budget (2026-07-07 run: all 128 entries spent
                             * before services.exe even spawned). */
                            if (fault_owner_peb && peb && fault_owner_peb != (void *)peb)
                            {
                                static volatile int xe_count = 0;
                                int xe = __sync_add_and_fetch(&xe_count, 1);
                                if (xe <= 256 || (xe % 1024) == 0)
                                {
                                    void *copy_pe = NULL;
                                    void *copy_owner = ios_jit_pool_copy_owner(jit_pc, &copy_pe);
                                    dprintf(STDERR_FILENO,
                                        "[xlate-exec] #%d teb=%p owner=%p pc=%p -> %p (copy pe=%p copy_owner=%p)\n",
                                        xe, (void *)thread_teb, fault_owner_peb,
                                        (void *)(uintptr_t)fault_pc, jit_pc, copy_pe, copy_owner);
                                }
                            }
                        }
                        if (jit_pc == (void *)(uintptr_t)fault_pc)
                        {
                            /* iOS-Mythic: if PC is in JIT pool RW alias range,
                             * redirect to RX alias (= PC - pool_size). FEX's
                             * emitted code lives at RX alias addresses, but
                             * sometimes a BR/BLR computes the RW alias via
                             * emitter math when our redirect interacts with
                             * vm_remap. */
                            extern void *ios_jit_rw_base_global;
                            extern size_t ios_jit_pool_size_global;
                            uintptr_t rw_base = (uintptr_t)ios_jit_rw_base_global;
                            uintptr_t rx_base2 = (uintptr_t)ios_jit_rx_base_global;
                            if (rw_base && rx_base2 && ios_jit_pool_size_global &&
                                fault_pc >= rw_base &&
                                fault_pc < rw_base + ios_jit_pool_size_global)
                            {
                                uintptr_t rx_pc = (uintptr_t)fault_pc - rw_base + rx_base2;
                                jit_pc = (void *)rx_pc;
                            }
                        }
                        if (jit_pc == (void *)(uintptr_t)fault_pc)
                        {
                            /* Not a known PE-image translation. Try the anon-alias
                             * table (FEX CodeBuffer / runtime JIT regions vm_remap'd
                             * from the JIT pool) — those have a separate RX alias
                             * that's actually executable. */
                            extern uintptr_t ios_jit_anon_alias_lookup_rx(uintptr_t);
                            uintptr_t rx_pc = ios_jit_anon_alias_lookup_rx((uintptr_t)fault_pc);
                            if (rx_pc) jit_pc = (void *)rx_pc;
                        }
                        if (jit_pc != (void *)(uintptr_t)fault_pc)
                        {
                            /* Plain pc redirect — even with x18==0. The old
                             * x18-restore trampoline clobbered x17, which is
                             * LIVE in FEX-emitted code (callret scratch) and
                             * in ARM64EC thunks. If the redirect target's
                             * code needs the TEB, its [x18,#imm] access
                             * faults and case 3 emulates it clobber-free. */
                            if (thread_teb && state.__x[18] == 0)
                            {
                                static volatile int redir2_count = 0;
                                int t2 = __sync_add_and_fetch(&redir2_count, 1);
                                if (t2 <= 10 || (t2 % 4096) == 0)
                                    dprintf(STDERR_FILENO,
                                        "[x18-redir2] #%d pc=%p -> jit=%p (x18 set via state)\n",
                                        t2, (void*)(uintptr_t)fault_pc, jit_pc);
                                /* Same set_state x18 experiment as case 3. */
                                state.__x[18] = thread_teb;
                            }
                            __darwin_arm_thread_state64_set_pc_fptr(state, jit_pc);
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                    }
                }
            }

            /* 3. Emulate [x18, #imm] accesses when x18 == 0.
             * iOS zeros x18 on context switch. EC/FEX code reads the TEB
             * through x18; with x18==0 the effective address IS the TEB
             * offset, so we can complete the access in-handler against the
             * real TEB (teb + fault_addr) and advance pc. Rn==18 in the
             * faulting instruction is the exact discriminator — a fault
             * with any other base register is NOT x18-caused and falls
             * through to real fault handling.
             *
             * This REPLACES the old x18-restore trampoline for data faults.
             * The trampoline clobbered x17 (its jump register) — fatal when
             * the interrupted code held a live value there. Two confirmed
             * kills (2026-07-04, after UNIXCALL-DIRECT widened the x18==0
             * windows): (a) FEX emitter loop `str w16,[x15,x17]` re-executed
             * with x17=pc → garbage address → eternal UNHANDLED; (b) ntdll
             * EC TEB-read sites trampolined with live x17 (pool pointers,
             * FP constants observed) → silent state corruption → heap
             * damage → libsystem_malloc died inside Metal texture creation.
             * Emulation clobbers NOTHING. x18 stays 0 afterwards; each
             * subsequent TEB access costs one fault until the next context
             * switch restores nothing — acceptable, bounded, correct. */
            if (!handled && state.__x[18] == 0 && thread_teb)
            {
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int is_exec_fault = (fault_addr == (uintptr_t)fault_pc);

                if (!is_exec_fault && fault_addr < 0x10000 &&
                    fault_pc >= 0x100000000ULL)
                {
                    uint32_t insn = *(uint32_t *)(uintptr_t)fault_pc;
                    int rn = (insn >> 5) & 0x1f;

                    /* ml157 PROBE (#36): the webhelper dies here. FEX emitted
                     * `movz w1,#0; ldr x1,[x1]` — the page-0 address was
                     * materialised into a SCRATCH register, so rn!=18 and the
                     * emulator above declines, making the fault fatal (5
                     * recursive repeats -> thread exit -> steam exit(1)).
                     *
                     * The open question is whether address 0 here is a TEB
                     * offset FEX spilled to a scratch reg, or a genuine guest
                     * NULL deref. Emulating the wrong one silently corrupts,
                     * so DO NOT widen the discriminator until this says which.
                     *
                     * Discriminators printed:
                     *  - the 16 insns before pc: an x18 SPILL (`mov xN,x18` /
                     *    `mrs`+TEB math) means TEB access; a guest-address
                     *    computation (adds/shifts from FEX guest regs) means a
                     *    real NULL deref.
                     *  - base reg VALUE vs fault_addr: equal => the register
                     *    literally held the small offset.
                     * Capped at 4 reports so a fault storm can't flood. */
                    if (rn != 18)
                    {
                        static int ios_x18_decline_reports;
                        if (ios_x18_decline_reports < 4)
                        {
                            const uint32_t *w = (const uint32_t *)(uintptr_t)fault_pc;
                            char buf[512];
                            int n = 0, k;
                            /* __x[] is x0..x28 only; fp/lr/sp are separate
                             * members and rn==31 is xzr/sp. Never index past 28. */
                            uint64_t rn_val = (rn < 29) ? state.__x[rn] :
                                              (rn == 29) ? state.__fp :
                                              (rn == 30) ? state.__lr : state.__sp;
                            ios_x18_decline_reports++;
                            for (k = -16; k <= 4 && n < (int)sizeof(buf) - 16; k++)
                                n += snprintf( buf + n, sizeof(buf) - n, "%s%08x",
                                               k ? " " : " [", w[k] ) + (k ? 0 : 0);
                            snprintf( buf + n, sizeof(buf) - n, "]" );
                            ERR( "[x18-decline] #%d pc=%p fault_addr=0x%lx insn=%08x rn=%d "
                                 "xRn=0x%llx (rn_val==fault_addr? %d) x18=0 teb=%p\n",
                                 ios_x18_decline_reports, (void *)(uintptr_t)fault_pc,
                                 (unsigned long)fault_addr, insn, rn,
                                 (unsigned long long)rn_val,
                                 rn_val == fault_addr, (void *)thread_teb );
                            ERR( "[x18-decline] #%d insns pc-64..pc+16:%s\n",
                                 ios_x18_decline_reports, buf );
                        }
                    }

                    if (rn == 18)
                    {
                        uintptr_t ea = thread_teb + fault_addr;
                        int rt = insn & 0x1f;
                        int emulated = 0;

                        switch (insn & 0xffc00000)
                        {
                        /* unsigned-offset immediate loads, base x18 */
                        case 0xf9400000: /* LDR Xt */
                            if (rt != 31) state.__x[rt] = *(uint64_t *)ea;
                            emulated = 1; break;
                        case 0xb9400000: /* LDR Wt (zero-extend) */
                            if (rt != 31) state.__x[rt] = *(uint32_t *)ea;
                            emulated = 1; break;
                        case 0x39400000: /* LDRB Wt */
                            if (rt != 31) state.__x[rt] = *(uint8_t *)ea;
                            emulated = 1; break;
                        case 0x79400000: /* LDRH Wt */
                            if (rt != 31) state.__x[rt] = *(uint16_t *)ea;
                            emulated = 1; break;
                        /* unsigned-offset immediate stores, base x18 */
                        case 0xf9000000: /* STR Xt */
                            *(uint64_t *)ea = (rt == 31) ? 0 : state.__x[rt];
                            emulated = 1; break;
                        case 0xb9000000: /* STR Wt */
                            *(uint32_t *)ea = (rt == 31) ? 0 : (uint32_t)state.__x[rt];
                            emulated = 1; break;
                        case 0x39000000: /* STRB Wt */
                            *(uint8_t *)ea = (rt == 31) ? 0 : (uint8_t)state.__x[rt];
                            emulated = 1; break;
                        case 0x79000000: /* STRH Wt */
                            *(uint16_t *)ea = (rt == 31) ? 0 : (uint16_t)state.__x[rt];
                            emulated = 1; break;
                        default: break;
                        }

                        /* LDP/STP Xt,Xt2,[x18,#imm] signed-offset (no writeback) */
                        if (!emulated && (insn & 0xffc00000) == 0xa9400000)
                        {
                            int rt2 = (insn >> 10) & 0x1f;
                            if (rt != 31)  state.__x[rt]  = *(uint64_t *)ea;
                            if (rt2 != 31) state.__x[rt2] = *(uint64_t *)(ea + 8);
                            emulated = 1;
                        }
                        else if (!emulated && (insn & 0xffc00000) == 0xa9000000)
                        {
                            int rt2 = (insn >> 10) & 0x1f;
                            *(uint64_t *)ea       = (rt == 31)  ? 0 : state.__x[rt];
                            *(uint64_t *)(ea + 8) = (rt2 == 31) ? 0 : state.__x[rt2];
                            emulated = 1;
                        }

                        /* GPR register-offset (`ldrb w8,[x18,x8]` killed boot
                         * 2026-07-04 19:39) and unscaled-immediate (LDUR/STUR)
                         * families, any size, loads+stores+signed loads. The
                         * hardware already computed the offset into fault_addr,
                         * so only size/opc/Rt semantics matter here. */
                        if (!emulated &&
                            ((insn & 0x3f200c00) == 0x38200800 ||   /* register offset */
                             (insn & 0x3f200c00) == 0x38000000))    /* unscaled imm9 */
                        {
                            int size = (insn >> 30) & 3;   /* 0=B 1=H 2=W 3=X */
                            int opc  = (insn >> 22) & 3;   /* 0=ST 1=LD 2/3=LDS */
                            uint64_t val = 0;
                            emulated = 1;
                            if (opc == 0)               /* store */
                            {
                                val = (rt == 31) ? 0 : state.__x[rt];
                                switch (size)
                                {
                                case 0: *(uint8_t  *)ea = (uint8_t)val;  break;
                                case 1: *(uint16_t *)ea = (uint16_t)val; break;
                                case 2: *(uint32_t *)ea = (uint32_t)val; break;
                                case 3: *(uint64_t *)ea = val;           break;
                                }
                            }
                            else if (opc == 1)          /* zero-extending load */
                            {
                                switch (size)
                                {
                                case 0: val = *(uint8_t  *)ea; break;
                                case 1: val = *(uint16_t *)ea; break;
                                case 2: val = *(uint32_t *)ea; break;
                                case 3: val = *(uint64_t *)ea; break;
                                }
                                if (rt != 31) state.__x[rt] = val;
                            }
                            else if (size == 3 && opc == 2)
                            {
                                /* PRFM (register/unscaled) — prefetch, no-op */
                            }
                            else                        /* sign-extending load */
                            {
                                int64_t sval = 0;
                                switch (size)
                                {
                                case 0: sval = *(int8_t  *)ea; break;
                                case 1: sval = *(int16_t *)ea; break;
                                case 2: sval = *(int32_t *)ea; break; /* LDRSW */
                                }
                                if (opc == 3) /* 32-bit target: Wt, zero upper */
                                    sval = (int64_t)(uint32_t)(int32_t)sval;
                                if (rt != 31) state.__x[rt] = (uint64_t)sval;
                            }
                        }

                        /* SIMD/FP register-offset + unsigned-offset loads/
                         * stores, base x18 (V=1, bit 26). `LDR Q0,[x18,x8]`
                         * (insn 3ce86a40) crashed the crypt32 cert-verify
                         * SIMD memcpy 2026-07-05. ea = thread_teb+fault_addr
                         * (hw already added the offset). Access width from
                         * {size, opc<1>}: size0+opc<1> = 128-bit Q, else
                         * 1<<size bytes (B/H/S/D). opc<0> (bit22): 1=load,
                         * 0=store. Loads write neon_state.__v[rt] (zeroing
                         * the upper lanes) and push it back immediately;
                         * stores read from it. */
                        if (!emulated && have_neon &&
                            ((insn & 0x3f200c00) == 0x3c200800 ||   /* SIMD register offset */
                             (insn & 0x3f000000) == 0x3d000000))    /* SIMD unsigned-offset imm */
                        {
                            int size = (insn >> 30) & 3;
                            int opc  = (insn >> 22) & 3;
                            int bytes = (size == 0 && (opc & 2)) ? 16 : (1 << size);
                            if (opc & 1)   /* load */
                            {
                                memset(&neon_state.__v[rt], 0, 16);
                                memcpy(&neon_state.__v[rt], (void *)ea, bytes);
                                thread_set_state(thread, ARM_NEON_STATE64,
                                                 (thread_state_t)&neon_state, neon_count);
                            }
                            else           /* store */
                            {
                                memcpy((void *)ea, &neon_state.__v[rt], bytes);
                            }
                            emulated = 1;
                        }

                        if (emulated)
                        {
                            static volatile int emul3_count = 0;
                            int e3 = __sync_add_and_fetch(&emul3_count, 1);
                            if (e3 <= 20 || (e3 % 4096) == 0)
                                dprintf(STDERR_FILENO,
                                    "[x18-emul3] #%d pc=%p insn=%08x teb+0x%llx rt=%d\n",
                                    e3, (void*)(uintptr_t)fault_pc, insn,
                                    (unsigned long long)fault_addr, rt);
                            /* EXPERIMENT: also set x18 in the written-back
                             * state. Project lore says thread_set_state
                             * doesn't preserve x18 — from early testing that
                             * may have been confounded. If it DOES stick,
                             * the silent-copy hole (NtCurrentTeb = mov
                             * x0,x18 propagating 0 without faulting) closes
                             * and emul3 should fire ~once per context
                             * switch instead of once per TEB access. Free
                             * either way — verify via emul3 rate + next-
                             * fault x18 values in the log. */
                            state.__x[18] = thread_teb;
                            __darwin_arm_thread_state64_set_pc_fptr(
                                state, (void *)(uintptr_t)(fault_pc + 4));
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                        else
                        {
                            /* x18-based but unrecognized encoding (writeback,
                             * register-offset, SIMD...). Log it — needs a new
                             * case above, NOT the old x17-clobbering
                             * trampoline. Falls through to real handling. */
                            dprintf(STDERR_FILENO,
                                "[x18-emul3] UNRECOGNIZED insn=%08x pc=%p teb+0x%llx\n",
                                insn, (void*)(uintptr_t)fault_pc,
                                (unsigned long long)fault_addr);
                        }
                    }
                }
            }

            /* 3.5. FEX unaligned LDAR/LDAPR/STLR backpatch.
             *
             * x86 has TSO ordering. FEX's MemoryOps lowers x86 TSO loads/stores
             * to ARM64 LDAPR/STLR (alignment-strict). Some x86 binaries do
             * legal *unaligned* loads (e.g. steamclient64.dll's packed
             * unpacker: `movl (%rsi),%ebx` with rsi unaligned) — those fault
             * on the LDAPR. FEX's HandleUnalignedAccess (Arm64.cpp:2072)
             * already knows how to recover by atomically rewriting the
             * instruction to LDR+DMB_LD (or DMB+STR for STLR). It only fires
             * on Windows EXCEPTION_DATATYPE_MISALIGNMENT — on iOS the Mach
             * handler sees EXC_BAD_ACCESS first.
             *
             * Replicate the FEX backpatch here so iOS gets the same recovery.
             * Encoding constants from FEX/FEXCore/Source/Utils/ArchHelpers/Arm64.cpp. */
            if (!handled)
            {
                extern void *ios_jit_rx_base_global;
                extern void *ios_jit_rw_base_global;
                extern size_t ios_jit_pool_size_global;
                uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
                uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
                size_t sz = ios_jit_pool_size_global;
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);

                if (rx && rw && sz && fault_pc >= rx && fault_pc < rx + sz)
                {
                    uintptr_t rw_pc = rw + (fault_pc - rx);
                    uint32_t insn = *(uint32_t *)(uintptr_t)fault_pc;

                    static const uint32_t LDAXR_MASK  = 0x3FFFFC00u;
                    static const uint32_t LDAR_INST   = 0x08DFFC00u;
                    static const uint32_t LDAPR_INST  = 0x38BFC000u;
                    static const uint32_t STLR_INST   = 0x089FFC00u;
                    static const uint32_t RCPC2_MASK  = 0x3FE00C00u;
                    static const uint32_t LDAPUR_INST = 0x19400000u;
                    static const uint32_t STLUR_INST  = 0x19000000u;
                    static const uint32_t LDR_INST    = 0x387F6800u; /* LDR (imm), unsigned-offset 0 */
                    static const uint32_t STR_INST    = 0x383F6800u;
                    static const uint32_t LDUR_INST   = 0x38400000u;
                    static const uint32_t STUR_INST   = 0x38000000u;
                    static const uint32_t DMB         = 0xD5033BBFu; /* dmb ish */
                    static const uint32_t DMB_LD      = 0xD5033DBFu; /* dmb ishld */

                    int patched = 0;
                    int adjust_pc = 0;

                    /* iOS-Mythic: gate the LDAR/STLR rewrite on the access
                     * being ACTUALLY unaligned for its size. The Mach
                     * EXC_BAD_ACCESS we catch here also covers plain guest
                     * NULL-derefs (addr=0x0, 0x8, ...). Those are aligned and
                     * must be raised as a normal SEGV — rewriting an LDAR/
                     * STLR there only delays the same fault and corrupts the
                     * exception path. Size encoded in insn[31:30]:
                     *   00=byte (always aligned), 01=halfword, 10=word, 11=dword. */
                    {
                        uint32_t access_size_lg2 = (insn >> 30) & 0x3;
                        uint64_t align_mask = (access_size_lg2 == 0) ? 0
                                            : ((1ULL << access_size_lg2) - 1);
                        if (align_mask && ((uint64_t)fault_addr & align_mask) == 0) {
                            /* Aligned — this is a genuine SEGV/BUS, not an
                             * unaligned-atomic-needs-backpatch case. Skip. */
                            goto skip_unaligned_backpatch;
                        }
                    }

                    if ((insn & LDAXR_MASK) == LDAR_INST ||
                        (insn & LDAXR_MASK) == LDAPR_INST)
                    {
                        /* LDAR/LDAPR → LDR + DMB_LD. Replace instruction in
                         * place with the regular LDR; FEX reserves the next
                         * slot for the half-barrier. */
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_ldr = LDR_INST | (Size << 30) | (Rn << 5) | Rt;
                        __atomic_store_n((volatile uint32_t *)(rw_pc + 4), DMB_LD, __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,         new_ldr, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)fault_pc, 8);
                        patched = 1;
                    }
                    else if ((insn & LDAXR_MASK) == STLR_INST)
                    {
                        /* STLR → DMB + STR. Half-barrier overwrites the slot
                         * before the STLR; PC backs up by 4. */
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_str = STR_INST | (Size << 30) | (Rn << 5) | Rt;
                        __atomic_store_n((volatile uint32_t *)(rw_pc - 4), DMB, __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,       new_str, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)(fault_pc - 4), 8);
                        adjust_pc = -4;
                        patched = 1;
                    }
                    else if ((insn & RCPC2_MASK) == LDAPUR_INST)
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_ldur = LDUR_INST | (Size << 30) | (Rn << 5) | Rt
                                           | (insn & (0x1FFu << 12));
                        __atomic_store_n((volatile uint32_t *)(rw_pc + 4), DMB_LD,   __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,         new_ldur, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)fault_pc, 8);
                        patched = 1;
                    }
                    else if ((insn & RCPC2_MASK) == STLUR_INST)
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_stur = STUR_INST | (Size << 30) | (Rn << 5) | Rt
                                           | (insn & (0x1FFu << 12));
                        __atomic_store_n((volatile uint32_t *)(rw_pc - 4), DMB,      __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,         new_stur, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)(fault_pc - 4), 8);
                        adjust_pc = -4;
                        patched = 1;
                    }

                    if (patched)
                    {
                        if (adjust_pc)
                            __darwin_arm_thread_state64_set_pc_fptr(state, (void *)(fault_pc + adjust_pc));
                        static volatile int ub_count = 0;
                        int n = __sync_add_and_fetch(&ub_count, 1);
                        if (n <= 5 || (n % 100) == 0)
                            dprintf(STDERR_FILENO,
                                    "[mach_exc] UNALIGNED-BACKPATCH #%d pc=0x%llx insn=0x%08x addr=0x%llx kind=%s\n",
                                    n, (unsigned long long)fault_pc, insn,
                                    (unsigned long long)fault_addr,
                                    adjust_pc ? "STLR/STLUR" : "LDAR/LDAPR/LDAPUR");
                        handled = 1;
                    }
                skip_unaligned_backpatch: ;
                }
            }

            /* 4. Emulate stores to JIT-pool RX aliases by redirecting them
             * to the corresponding JIT-pool RW alias address. iOS dual-map
             * blocks W on the RX side even with vm_protect+VM_PROT_COPY,
             * so STR/STP instructions whose target lands in JIT-pool RX
             * have to be emulated. The instruction's other side-effects
             * (Rt unchanged, no flag updates) are nil for STR/STP/STRB/STRH. */
            if (!handled)
            {
                extern void *ios_jit_rx_base_global;
                extern void *ios_jit_rw_base_global;
                extern size_t ios_jit_pool_size_global;
                extern uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr);
                uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
                uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
                size_t sz = ios_jit_pool_size_global;
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                /* Two cases: (a) fault on JIT pool RX directly, route via the
                 * RW alias by offset translation. (b) fault on a user-VA that
                 * was vm_remap'd from JIT pool RX (e.g. FEX CodeBuffer): use
                 * the secondary alias table to find the user_VA → RW alias
                 * mapping. */
                uintptr_t rw_addr = 0;
                int in_jit = (rx && rw && sz &&
                              fault_addr >= rx && fault_addr < rx + sz);
                if (in_jit) {
                    rw_addr = rw + (fault_addr - rx);
                } else {
                    rw_addr = ios_jit_anon_alias_lookup(fault_addr);
                }
                if (rw_addr && (uintptr_t)fault_pc >= 0x100000000ULL)
                {
                    uint32_t insn = *(uint32_t *)(uintptr_t)fault_pc;
                    int emulated = 0;
                    /* STP (SIMD&FP, signed offset, 128-bit Q): 10 101 1 1 0 0 0 imm7 Rt2 Rn Rt
                     *   pattern bits 31-22: 10 1011 1000  → top10 = 0x2B8 (= bits 31..22)
                     *   So mask 0xFFC00000 = top10. Match 0x2B8 << 22 = 0xAE000000? Hmm.
                     * Actually: STP q0,q1,[xn,#imm] is `1010 1101 0010 ... `
                     * STP q,q (signed offset): 0xAD0 (top 12), so mask 0xFFE00000 == 0xAD000000.
                     * STP q,q (pre/post-index variants): 0xAD8, 0xACC, etc.
                     * For now, emulate the family: top 7 bits = 0b1010110, bit 31:25 = 0x56,
                     * mask 0xFE000000 matches 0xAC000000 — covers 64/128-bit SIMD STP variants. */
                    if (have_neon && ((insn & 0xFEC00000) == 0xAC000000 || (insn & 0xFEC00000) == 0xAD000000))
                    {
                        /* SIMD STP variants — store 2x 128-bit registers */
                        int rt = insn & 0x1f;
                        int rt2 = (insn >> 10) & 0x1f;
                        memcpy((void *)rw_addr, &neon_state.__v[rt], 16);
                        memcpy((void *)(rw_addr + 16), &neon_state.__v[rt2], 16);
                        emulated = 1;
                    }
                    /* STR (immediate, unsigned offset, 64-bit): 1111 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xf9000000)
                    {
                        int rt = insn & 0x1f;
                        *(uint64_t *)rw_addr = state.__x[rt];
                        emulated = 1;
                    }
                    /* STR (immediate, unsigned offset, 32-bit): 1011 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xb9000000)
                    {
                        int rt = insn & 0x1f;
                        *(uint32_t *)rw_addr = (uint32_t)state.__x[rt];
                        emulated = 1;
                    }
                    /* STRB (immediate, unsigned offset, 8-bit): 0011 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0x39000000)
                    {
                        int rt = insn & 0x1f;
                        *(uint8_t *)rw_addr = (uint8_t)state.__x[rt];
                        emulated = 1;
                    }
                    /* STRH (immediate, unsigned offset, 16-bit): 0111 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0x79000000)
                    {
                        int rt = insn & 0x1f;
                        *(uint16_t *)rw_addr = (uint16_t)state.__x[rt];
                        emulated = 1;
                    }
                    /* STP (signed offset, 64-bit): 10101001 00 imm7 Rt2 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xa9000000)
                    {
                        int rt = insn & 0x1f;
                        int rt2 = (insn >> 10) & 0x1f;
                        *(uint64_t *)rw_addr = state.__x[rt];
                        *(uint64_t *)(rw_addr + 8) = state.__x[rt2];
                        emulated = 1;
                    }
                    /* STP (signed offset, 32-bit): 00101001 00 imm7 Rt2 Rn Rt */
                    else if ((insn & 0xffc00000) == 0x29000000)
                    {
                        int rt = insn & 0x1f;
                        int rt2 = (insn >> 10) & 0x1f;
                        *(uint32_t *)rw_addr = (uint32_t)state.__x[rt];
                        *(uint32_t *)(rw_addr + 4) = (uint32_t)state.__x[rt2];
                        emulated = 1;
                    }
                    /* STR (register, 64-bit): 1111 1000 001 Rm option S 10 Rn Rt */
                    else if ((insn & 0xffe00c00) == 0xf8200800)
                    {
                        int rt = insn & 0x1f;
                        *(uint64_t *)rw_addr = state.__x[rt];
                        emulated = 1;
                    }
                    /* STLR (Store-Release Register, 64-bit):
                     *   1100 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0xc89ffc00)
                     * Used by FEX's HandleUnalignedAccess backpatch
                     * (`std::atomic_ref<uint32_t>(PC).store(..., release)` → STLR).
                     * Without this we infinite-loop on unaligned atomic faults
                     * because FEX can't patch its own JIT block on iOS RX-only memory. */
                    else if ((insn & 0xfffffc00) == 0xc89ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint64_t *)rw_addr, state.__x[rt], __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* STLR (Store-Release Register, 32-bit):
                     *   1000 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0x889ffc00)
                     * Same use case — FEX's backpatch is a 32-bit instruction store. */
                    else if ((insn & 0xfffffc00) == 0x889ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint32_t *)rw_addr, (uint32_t)state.__x[rt], __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* STLRH (Store-Release 16-bit):
                     *   0100 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0x489ffc00) */
                    else if ((insn & 0xfffffc00) == 0x489ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint16_t *)rw_addr, (uint16_t)state.__x[rt], __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* STLRB (Store-Release 8-bit):
                     *   0000 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0x089ffc00) */
                    else if ((insn & 0xfffffc00) == 0x089ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint8_t *)rw_addr, (uint8_t)state.__x[rt], __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* STR (register, 32-bit): 1011 1000 001 Rm option S 10 Rn Rt */
                    else if ((insn & 0xffe00c00) == 0xb8200800)
                    {
                        int rt = insn & 0x1f;
                        *(uint32_t *)rw_addr = (uint32_t)state.__x[rt];
                        emulated = 1;
                    }
                    /* STR (immediate, post/pre-index, 64-bit): 1111 1000 00 0imm9 0[10]1 Rn Rt */
                    else if ((insn & 0xffe00000) == 0xf8000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        *(uint64_t *)rw_addr = state.__x[rt];
                        emulated = 1;
                        /* Post-index (bits 11:10 = 01) / pre-index (bits 11:10 = 11):
                         * MUST update Rn += signed imm9. Without this, memcpy-style
                         * loops would write the same address forever. */
                        int idx_mode = (insn >> 10) & 3;  // bits 11:10
                        if (idx_mode == 1 || idx_mode == 3)
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;  // sign-extend 9-bit
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* STR (immediate, post/pre-index, 32-bit): 1011 1000 00 0imm9 0[10]1 Rn Rt */
                    else if ((insn & 0xffe00000) == 0xb8000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        *(uint32_t *)rw_addr = (uint32_t)state.__x[rt];
                        emulated = 1;
                        int idx_mode = (insn >> 10) & 3;
                        if (idx_mode == 1 || idx_mode == 3)
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* STRB (immediate, post/pre-index, 8-bit): 0011 1000 00 0imm9 0[10]1 Rn Rt
                     * Hits when iOS memcpy handles the trailing bytes after the
                     * 8-byte D-store loop completes (660 bytes = 82*8 + 4 bytes
                     * tail; the tail is byte-by-byte). */
                    else if ((insn & 0xffe00000) == 0x38000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        *(uint8_t *)rw_addr = (uint8_t)state.__x[rt];
                        emulated = 1;
                        int idx_mode = (insn >> 10) & 3;
                        if (idx_mode == 1 || idx_mode == 3)
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* STRH (immediate, post/pre-index, 16-bit): 0111 1000 00 0imm9 0[10]1 Rn Rt */
                    else if ((insn & 0xffe00000) == 0x78000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        *(uint16_t *)rw_addr = (uint16_t)state.__x[rt];
                        emulated = 1;
                        int idx_mode = (insn >> 10) & 3;
                        if (idx_mode == 1 || idx_mode == 3)
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* SIMD/FP STR (immediate, post/pre-index, D-reg = 64-bit):
                     * 11 111 1 00 00 0 imm9 idx Rn Rt   — encoding 0xfc000400 base.
                     * The fc008600 = `str d0, [x16], #8` from iOS memcpy hits
                     * this when copying compiled FEX blocks to RX-only memory. */
                    else if ((insn & 0xffe00000) == 0xfc000000 && (insn & 0xc00) != 0)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            /* Low 64 bits of the 128-bit Q-reg = D-reg. */
                            memcpy((void *)rw_addr, &neon_state.__v[rt], 8);
                            emulated = 1;
                            int idx_mode = (insn >> 10) & 3;
                            if (idx_mode == 1 || idx_mode == 3)
                            {
                                int rn = (insn >> 5) & 0x1f;
                                int imm9 = (insn >> 12) & 0x1ff;
                                if (imm9 & 0x100) imm9 |= ~0x1ff;
                                state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                            }
                        }
                    }
                    /* SIMD/FP STR (immediate, post/pre-index, S-reg = 32-bit):
                     * 10 111 1 00 00 0 imm9 idx Rn Rt   — base 0xbc000400. */
                    else if ((insn & 0xffe00000) == 0xbc000000 && (insn & 0xc00) != 0)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            memcpy((void *)rw_addr, &neon_state.__v[rt], 4);
                            emulated = 1;
                            int idx_mode = (insn >> 10) & 3;
                            if (idx_mode == 1 || idx_mode == 3)
                            {
                                int rn = (insn >> 5) & 0x1f;
                                int imm9 = (insn >> 12) & 0x1ff;
                                if (imm9 & 0x100) imm9 |= ~0x1ff;
                                state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                            }
                        }
                    }
                    /* SIMD/FP STR (immediate, post/pre-index, Q-reg = 128-bit):
                     * 00 111 1 00 10 0 imm9 idx Rn Rt   — base 0x3c800400. */
                    else if ((insn & 0xffe00000) == 0x3c800000 && (insn & 0xc00) != 0)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            memcpy((void *)rw_addr, &neon_state.__v[rt], 16);
                            emulated = 1;
                            int idx_mode = (insn >> 10) & 3;
                            if (idx_mode == 1 || idx_mode == 3)
                            {
                                int rn = (insn >> 5) & 0x1f;
                                int imm9 = (insn >> 12) & 0x1ff;
                                if (imm9 & 0x100) imm9 |= ~0x1ff;
                                state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                            }
                        }
                    }
                    /* GPR STR (immediate, unsigned offset, 64-bit X-reg):
                     *   1111 1001 00 imm12 Rn Rt   (base 0xf9000000, mask 0xffc00000)
                     * Hits for `str xN, [xM, #imm]` and `str xN, [xM]` —
                     * what the C compiler emits for `*ptr = uint64_value`.
                     * Wine's PE loader / ARM64EC compiler-generated code triggers this
                     * when initializing data in a page that's been mprotect'd RX-only
                     * on iOS. fault_addr already includes the imm12 offset. */
                    else if ((insn & 0xffc00000) == 0xf9000000)
                    {
                        int rt = insn & 0x1f;
                        *(uint64_t *)rw_addr = state.__x[rt];
                        emulated = 1;
                    }
                    /* GPR STR (immediate, unsigned offset, 32-bit W-reg):
                     *   1011 1001 00 imm12 Rn Rt   (base 0xb9000000, mask 0xffc00000)
                     * `*ptr32 = uint32_value` analogue. */
                    else if ((insn & 0xffc00000) == 0xb9000000)
                    {
                        int rt = insn & 0x1f;
                        *(uint32_t *)rw_addr = (uint32_t)state.__x[rt];
                        emulated = 1;
                    }
                    /* SIMD/FP STR (immediate, unsigned offset, D-reg): 11 111 1 01 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xfd000000)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            memcpy((void *)rw_addr, &neon_state.__v[rt], 8);
                            emulated = 1;
                        }
                    }
                    /* SIMD/FP STR (immediate, unsigned offset, S-reg): 10 111 1 01 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xbd000000)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            memcpy((void *)rw_addr, &neon_state.__v[rt], 4);
                            emulated = 1;
                        }
                    }
                    /* SIMD/FP STR (immediate, unsigned offset, Q-reg): 00 111 1 01 10 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0x3d800000)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            memcpy((void *)rw_addr, &neon_state.__v[rt], 16);
                            emulated = 1;
                        }
                    }
                    if (emulated)
                    {
                        /* Advance PC past the emulated instruction */
                        __darwin_arm_thread_state64_set_pc_fptr(state,
                            (void *)(uintptr_t)(fault_pc + 4));
                        handled = 1;
                        static volatile int emul_count = 0;
                        int ec = __sync_add_and_fetch(&emul_count, 1);
                        if (ec <= 5 || (ec % 1000) == 0)
                        {
                            /* Verify dual-map sharing: read back via the RX
                             * (original) address and compare to what we wrote
                             * via RW. If they match, the dual-map is working
                             * end-to-end. */
                            uint64_t rw_val = *(uint64_t *)rw_addr;
                            uint64_t rx_val = *(uint64_t *)fault_addr;
                            dprintf(STDERR_FILENO,
                                "[mach_exc] EMULATED STR #%d pc=%p insn=%08x rx=%p→rw=%p"
                                " | dual-map readback rx=%llx rw=%llx %s\n",
                                ec, (void*)(uintptr_t)fault_pc, insn,
                                (void*)fault_addr, (void*)rw_addr,
                                (unsigned long long)rx_val,
                                (unsigned long long)rw_val,
                                (rx_val == rw_val) ? "OK" : "MISMATCH");
                        }
                    }
                }
            }

            /* iOS-Mythic RECLAIM RECOVERY (FEX-2607 Thumper): a page that Wine/FEX
             * consider committed can be reclaimed by iOS under memory pressure —
             * 2607's per-thread 96MB LookupCaches push the app over the jetsam
             * limit, so committed L1/L2/code pages get dropped and the re-access
             * faults with no other handler -> terminate. Force the page back with
             * mprotect(RW); it returns zero-filled, which is functionally correct
             * for FEX's caches (a zero L1/L2 slot reads as "empty" -> FEX
             * recompiles). Gated to the FEX host-arena band (~0x7Cxx..0x80xx) so
             * it can't mask guest/dyld/null-deref faults, with a 16-slot per-page
             * repeat guard so an ineffective mprotect can't spin forever. */
            {
                uint64_t fa = (uint64_t)fault_addr;
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);

                /* task #34 (ml74): EXECUTE fault on a code page — the RW grant
                 * below can never fix it (observed: retry#1..51 on
                 * 0x7ecaf00000, RW mprotect "succeeds", same fault forever;
                 * and the fatal walk in the pool RX view at 0x125115ce0 whose
                 * page had become prot=RW max_prot=RW). Handle code ranges
                 * FIRST: try to restore R|X — works when the pool/copy
                 * mapping is intact and only lost its protection. If mprotect
                 * RX fails, max_prot lost X = the mapping was REPLACED (see
                 * [jit-tripwire] in virtual_ios.c) — nothing in-handler can
                 * fix that; log the vm_region ground truth and fall through
                 * so the fault surfaces instead of spinning. */
                if (!handled && fa == (uint64_t)fault_pc)
                {
                    extern void *ios_jit_rx_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uint64_t rx = (uint64_t)(uintptr_t)ios_jit_rx_base_global;
                    int in_pool_rx = rx && fa >= rx && fa < rx + ios_jit_pool_size_global;
                    int in_band    = (fa >= 0x7C00000000ULL && fa < 0x8000000000ULL);

                    if (in_pool_rx || in_band)
                    {
                        enum { XR_PAGE = 0x4000 };
                        uint64_t pg = fa & ~(uint64_t)(XR_PAGE - 1);
                        static volatile uint64_t xr_pg[16] = {0};
                        static volatile uint32_t xr_n[16]  = {0};
                        int s = (int)((pg >> 14) & 15);
                        int giveup = 0;
                        if (xr_pg[s] == pg) { if (++xr_n[s] > 8) giveup = 1; }
                        else { xr_pg[s] = pg; xr_n[s] = 1; }
#ifndef MADV_FREE_REUSE
#define MADV_FREE_REUSE 8
#endif
                        if (!giveup)
                        {
                            /* Restore R|X. Works when the pool RX view / arm64ec
                             * pool-copy mapping is intact and only lost protection
                             * under reclaim. MADV_FREE_REUSE cancels any residual
                             * volatility so the page isn't immediately re-harvested. */
                            int mpr = mprotect( (void *)(uintptr_t)pg, XR_PAGE, PROT_READ | PROT_EXEC );
                            int errno_save = errno;
                            int reuse = madvise( (void *)(uintptr_t)pg, XR_PAGE, MADV_FREE_REUSE );
                            static volatile int xrc = 0;
                            int xrcn = __sync_fetch_and_add(&xrc, 1);
                            if (xrcn < 40 || (xrcn % 50) == 0)
                                dprintf(STDERR_FILENO,
                                    "[exec-recover] pg=0x%llx fault=0x%llx mprotect_rx=%d(errno=%d) reuse-cancel=%d retry#%u %s\n",
                                    (unsigned long long)pg, (unsigned long long)fa, mpr, errno_save,
                                    reuse, xr_n[s], in_pool_rx ? "pool-rx" : "band");
                            if (mpr == 0) handled = 1;
                            /* ml133: mprotect(RX) on debugger-blessed pool memory
                             * returns EACCES *unconditionally* — it is a platform
                             * rule (only StikDebug's original blessed mapping may
                             * be executable), NOT evidence that the mapping was
                             * replaced, and the comment below has been reading it
                             * that way for months. So recovery has never actually
                             * been attempted here.
                             *
                             * What we DO know (ml104 byte-compare): the faulting
                             * page is READABLE and its content is byte-identical
                             * to the on-disk DLL. So the mapping is intact and the
                             * page merely needs faulting back in. Force that from
                             * the kernel side with mach_vm_read_overwrite — a
                             * syscall, so it cannot itself fault this handler
                             * thread the way a user-space load could — then retry
                             * the instruction. If exec really is gone the retry
                             * re-faults and the giveup counter above (8 tries per
                             * page slot) surfaces it instead of spinning. */
                            else if (in_pool_rx)
                            {
                                uint64_t probe[2] = { 0, 0 };
                                mach_vm_size_t got = 0;
                                kern_return_t kr = mach_vm_read_overwrite(
                                        mach_task_self(), (mach_vm_address_t)pg, sizeof(probe),
                                        (mach_vm_address_t)&probe, &got );
                                if (kr == KERN_SUCCESS && got == sizeof(probe))
                                {
                                    sys_icache_invalidate( (void *)(uintptr_t)pg, XR_PAGE );
                                    handled = 1;
                                }
                                if (xrcn < 40 || (xrcn % 50) == 0)
                                    dprintf(STDERR_FILENO,
                                        "[exec-recover] pg=0x%llx read-touch kr=%d got=%llu word0=0x%llx -> %s\n",
                                        (unsigned long long)pg, (int)kr,
                                        (unsigned long long)got, (unsigned long long)probe[0],
                                        handled ? "RETRY" : "surface");
                            }
                            /* else: mprotect RX failed => max_prot lost EXECUTE =>
                             * the code page was REPLACED by a plain RW mapping
                             * ([jit-tripwire] names the culprit). Nothing here can
                             * re-add X; leave handled=0 and fall through to the
                             * unhandled path, which dumps vm_region ground truth
                             * and surfaces the fault instead of spinning forever. */
                        }
                    }
                }

                /* DATA fault reclaim recovery in the FEX host-arena band
                 * (FEX-2607 Thumper path): a page Wine/FEX consider committed
                 * gets reclaimed under memory pressure — 2607's per-thread 96MB
                 * LookupCaches push over the jetsam limit, so L1/L2/cache pages
                 * are dropped and the re-access faults with no other handler.
                 * Force the page back with mprotect(RW); zero-filled is correct
                 * for FEX's caches (a zero L1/L2 slot reads "empty" -> recompile).
                 * Gated to the host-arena band AND to non-execute faults so it
                 * can't shadow the R|X path above or mask guest/null-deref faults.
                 * Task #22: cap was >4 — Steam's download pressure re-harvested
                 * the same still-volatile page 5+ times; MADV_FREE_REUSE makes
                 * recovery permanent, the higher cap is a belt for residual
                 * volatility. */
                /* Correctness guard, NOT a fix for anything observed: this band
                 * ([496G,512G)) must never claim the JIT pool's own RW alias,
                 * because pool writes have their own STR-emulation path and this
                 * one "recovers" by mapping fresh ZERO pages. It is a no-op at
                 * the default alias placement (0x7000000000 is outside the
                 * band) and exists so a future relocation can't silently couple
                 * to this handler.
                 * HONEST NOTE: this was added on the theory that the band was
                 * why relocating the alias into it caused exec faults. It was
                 * NOT — ml98 kept the exclusion, kept the alias at
                 * 0x7c00000000, and still took 16 faults (ml97 also 16). The
                 * real coupling is still unidentified; do not cite this as the
                 * explanation. */
                {
                    extern void *ios_jit_rw_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uintptr_t rwb = (uintptr_t)ios_jit_rw_base_global;
                    if (rwb && ios_jit_pool_size_global &&
                        fa >= rwb && fa < rwb + ios_jit_pool_size_global)
                        goto skip_reclaim_band;
                }
                if (!handled && fa != (uint64_t)fault_pc &&
                    fa >= 0x7C00000000ULL && fa < 0x8000000000ULL)
                {
                    static volatile uint64_t rr_pg[16] = {0};
                    static volatile uint32_t rr_n[16]  = {0};
                    /* iOS uses 16KB host pages. NOTE: `host_page_size` in this
                     * file resolves to the Mach *function*, not a size — using
                     * it as a value gave a garbage mask (mprotect EINVAL). */
                    enum { RR_PAGE = 0x4000 };
                    uint64_t pg = fa & ~(uint64_t)(RR_PAGE - 1);
                    int s = (int)((pg >> 14) & 15);
                    int giveup = 0;
                    if (rr_pg[s] == pg) { if (++rr_n[s] > 64) giveup = 1; }
                    else { rr_pg[s] = pg; rr_n[s] = 1; }
                    if (!giveup)
                    {
                        /* ml95 (task #34): the "FEX host-arena band" assumption
                         * behind the zero-fill below is STALE. Wine's PE images
                         * now cluster in this same [496G,512G) band — ml95 took
                         * a fault on pg=0x7ed1be0000 (507.1G) which is a loaded
                         * MODULE BASE, and images were measured at 505.8G. For a
                         * FEX cache page a fresh zero page is correct (reads
                         * "empty" -> recompile); for a module it silently
                         * DESTROYS the code, and the thread then executes zeros
                         * or leaks a pool address into the guest RIP
                         * ([rip-leak] named exactly that module, rva 0x109835).
                         * Never zero-fill a page that belongs to a loaded image:
                         * restore protection if the mapping survives, otherwise
                         * surface the fault instead of corrupting it away. */
                        extern unsigned long long ios_jit_module_base_for_va( unsigned long long va,
                                                                              unsigned long long *size_out );
                        /* ml306 (task #53): capture Wine's committed-state BEFORE recovery mutates
                         * anything. This is THE discriminator for whether zero-fill is safe here:
                         *   VPROT_COMMITTED (0x20) set  -> page held live data; zeros = DATA LOSS or
                         *                                  a masked use-after-free. ml305's fatal
                         *                                  (null+0x90 through a pointer read from
                         *                                  this band, [reclaim-recover] firing
                         *                                  mid-exception) is the suspected result.
                         *   clear                       -> lazy-reservation first touch; zeros are
                         *                                  the contract and recovery is benign.
                         * Measurement only for now -- behaviour unchanged until at least one run
                         * says how the 2-4 events per run split. */
                        extern unsigned char ios_reclaim_page_vprot( unsigned long long va );
                        unsigned char pg_vprot = ios_reclaim_page_vprot( pg );
                        unsigned long long mod_size = 0;
                        unsigned long long mod_base = ios_jit_module_base_for_va( pg, &mod_size );
                        int mpr = mprotect( (void *)(uintptr_t)pg, RR_PAGE, PROT_READ | PROT_WRITE );
                        int errno_save = errno;
                        int used_mmap = 0;
                        if (mpr != 0 && !mod_base)  /* scratch page: fresh zeros ARE the contract */
                        {
                            void *r = mmap( (void *)(uintptr_t)pg, RR_PAGE, PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0 );
                            used_mmap = (r == (void *)(uintptr_t)pg);
                        }
                        else if (mpr != 0)
                        {
                            static volatile int mrc = 0;
                            if (__sync_fetch_and_add(&mrc, 1) < 24)
                                dprintf(STDERR_FILENO,
                                    "[reclaim-recover] REFUSED zero-fill of LOADED MODULE page pg=0x%llx module=0x%llx+0x%llx rva=0x%llx errno=%d — zeros would destroy code, surfacing fault\n",
                                    (unsigned long long)pg, mod_base, mod_size,
                                    (unsigned long long)(pg - mod_base), errno_save);
                        }
                        int reuse = madvise( (void *)(uintptr_t)pg, RR_PAGE, MADV_FREE_REUSE );
                        /* iOS-Mythic ml329 (#53 DISCRIMINATOR): remember every page we
                         * zero-fill, so a later crash can be tested against them instead
                         * of inferred.
                         *
                         * ml326+ml328 both died in FEXCore's IntrusivePooledAllocator
                         * (ClaimBufferImpl) reading a NULL `next` at offset 8 of a
                         * fextl::list node -- i.e. a list node full of zeros. Those nodes
                         * are aligned_alloc'd into FEX's jemalloc heap, which lives in the
                         * same [0x7c,0x80) band this recovery path re-mmaps. That makes
                         * "iOS reclaimed the page and we handed the allocator zeros" the
                         * leading hypothesis -- but the existing verdict string reads
                         * WINE's vprot, which is 0 for memory FEX allocated through its own
                         * VirtualAlloc2 path, so it prints "zeros OK" either way and cannot
                         * settle it. Record the pages; ios_reclaim_pages_report() prints
                         * them at the fatal SEGV so the two can be correlated directly. */
                        ios_reclaim_note_page( pg );
                        static volatile int rc = 0;
                        int rcn = __sync_fetch_and_add(&rc, 1);
                        if (rcn < 40 || (rcn % 50) == 0)
                            dprintf(STDERR_FILENO,
                                "[reclaim-recover] pg=0x%llx fault=0x%llx mprotect=%d(errno=%d) mmap=%d reuse-cancel=%d retry#%u vprot=0x%02x %s\n",
                                (unsigned long long)pg, (unsigned long long)fa, mpr, errno_save,
                                used_mmap, reuse, rr_n[s], pg_vprot,
                                (pg_vprot & 0x20) ? "WAS-COMMITTED(zeros=DATA-LOSS/UAF!)"
                                                  : "not-committed(lazy first touch, zeros OK)");
                        if (mpr == 0 || used_mmap) handled = 1;
                    }
                }
skip_reclaim_band: ;
            }

            if (handled)
                thread_set_state( thread, ARM_THREAD_STATE64,
                                  (thread_state_t)&state, count );
            else
            {
                /* Rate-limit: log first 5 unhandled faults then every 100th */
                static volatile int unhandled_count = 0;
                int cnt = __sync_add_and_fetch(&unhandled_count, 1);
                /* iOS-Mythic: ALWAYS dump for "terminal-looking" faults
                 * — fault PC outside any plausible mapped region (low addr
                 * < 0x100000000 OR in dyld_shared_cache range 0x3xxxx00000+).
                 * Path-init memcpy faults happen at JIT-pool PCs and burn
                 * the cnt<=5 budget; without this terminal crashes were
                 * never dumped. */
                uint64_t fault_pc_check = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int terminal_pc = (fault_pc_check < 0x100000000ULL ||
                                   (fault_pc_check >> 32) >= 0x300);
                /* iOS-Mythic 2026-05-15: compact per-fault line + first-seen
                 * guest RIP tracker. The Thumper fault loop has 13K+ UNHANDLED
                 * exceptions at JIT-pool PCs; the current cnt<=5 gate hides
                 * which guest function(s) the loop runs over. Capture State.RIP
                 * for every fault (cheap, ~80 bytes/line) so we can correlate
                 * fault PC ranges with guest RIPs offline. */
                {
                    uintptr_t teb_q = 0; void *tramp_q = NULL;
                    ios_lookup_thread(thread, &teb_q, &tramp_q);
                    void *fex_state_q = NULL;
                    if (teb_q)
                    {
                        void *cpuarea = *(void**)(teb_q + 0x1788);
                        if (cpuarea) fex_state_q = *(void**)((char*)cpuarea + 0x30);
                    }
                    uint64_t state_rip_q = fex_state_q ?
                        ((uint64_t*)fex_state_q)[0x18 / 8] : 0;
                    /* First-seen tracker: 32-slot hash by RIP. */
                    static volatile uint64_t seen_rip[32] = {0};
                    static volatile uint32_t seen_count[32] = {0};
                    int slot = (int)((state_rip_q >> 4) & 31);
                    int first_seen = 0;
                    if (seen_rip[slot] != state_rip_q)
                    {
                        /* Linear probe to find empty / matching slot */
                        int s;
                        for (s = 0; s < 32; s++)
                        {
                            int k = (slot + s) & 31;
                            if (seen_rip[k] == state_rip_q) { slot = k; break; }
                            if (seen_rip[k] == 0 &&
                                __sync_bool_compare_and_swap(&seen_rip[k], 0, state_rip_q))
                            { slot = k; first_seen = 1; break; }
                        }
                    }
                    __sync_add_and_fetch(&seen_count[slot], 1);

                    /* ml261 LIVELOCK BREAKER, keyed on the faulting PAGE.
                     *
                     * ml261 burned its whole run on 49,500+ faults at ONE address --
                     * previous runs peaked near 4,000. Signature:
                     *   insn f81f0ff3 = str x19,[sp,#-16]!   (a prologue push)
                     *   sp=0x73d16aff40, fault addr=0x73d16aff30  (16 bytes below sp)
                     *   [fault-rgn] page=0x73d16ac000 vprot prev/this/next=00/00/23
                     *   [fault-rgn] NO wine view -- Wine doesn't own this addr
                     * i.e. a stack growing into an UNCOMMITTED page (the page above IS
                     * committed) on a stack Wine does not own, so virtual_handle_fault
                     * declines, nothing commits it, and the access retries forever.
                     *
                     * The existing SEGV LOOP FATAL guard cannot catch this: it keys on
                     * the PC, and here two PCs alternate (0x13b5f2004 prologue and
                     * 0x1026b3188 memcpy) over the SAME page. Key on the page instead.
                     *
                     * This does NOT fix the missing commit -- it stops one page from
                     * eating an entire run, and dumps the region layout around it so the
                     * owner can be identified and the real fix aimed correctly. */
                    {
                        static volatile uint64_t stuck_page;
                        static volatile uint32_t stuck_n;
                        uint64_t fpage = (uint64_t)fault_addr & ~0x3fffull;

                        if (fpage && fpage == stuck_page)
                        {
                            uint32_t n = __sync_add_and_fetch(&stuck_n, 1);
                            if (n == 2048)
                            {
                                mach_vm_address_t ra = (mach_vm_address_t)(fpage - 0x8000);
                                int i;
                                dprintf(STDERR_FILENO,
                                    "[fault-stuck] page 0x%llx faulted %u times with NO progress "
                                    "(pc=0x%llx sp=0x%llx) -- region map around it:\n",
                                    (unsigned long long)fpage, n,
                                    (unsigned long long)fault_pc_check,
                                    (unsigned long long)__darwin_arm_thread_state64_get_sp(state));
                                for (i = 0; i < 6; i++)
                                {
                                    mach_vm_size_t rs = 0;
                                    vm_region_basic_info_data_64_t rbi;
                                    mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
                                    mach_port_t ro = MACH_PORT_NULL;
                                    mach_vm_address_t q = ra;
                                    if (mach_vm_region( mach_task_self(), &q, &rs,
                                                        VM_REGION_BASIC_INFO_64,
                                                        (vm_region_info_t)&rbi, &rc, &ro ) != KERN_SUCCESS)
                                    {
                                        dprintf(STDERR_FILENO,
                                            "[fault-stuck]   probe 0x%llx -> no region above\n",
                                            (unsigned long long)ra);
                                        break;
                                    }
                                    dprintf(STDERR_FILENO,
                                        "[fault-stuck]   region 0x%llx +0x%llx prot=%d/%d %s\n",
                                        (unsigned long long)q, (unsigned long long)rs,
                                        rbi.protection, rbi.max_protection,
                                        (q <= fpage && fpage < q + rs) ? "  <== FAULTING PAGE" : "");
                                    ra = q + rs;
                                }
                            }
                        }
                        else
                        {
                            stuck_page = fpage;
                            stuck_n = 0;
                        }
                    }

                    if (cnt <= 50 || first_seen || (cnt % 500) == 0)
                    {
                        dprintf(STDERR_FILENO,
                            "[fault_rip] cnt=%d rip=0x%llx pc=0x%llx%s\n",
                            cnt, (unsigned long long)state_rip_q,
                            (unsigned long long)fault_pc_check,
                            first_seen ? " [first]" : "");
                    }
                    /* TEMP [rip-leak] task#34 ml64-class: guest RIP inside a
                     * JIT-POOL mapping means a pool-translated pointer leaked
                     * into guest control flow (guest must only ever see PE
                     * VAs; ml64 ran away executing dbghelp's pool ARM64 .text
                     * as x86). Name the module+RVA and dump the guest return
                     * stack so the SOURCE of the poisoned pointer is
                     * identifiable. Capped. STRIP BEFORE COMMIT. */
                    if (first_seen && state_rip_q)
                    {
                        extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                        uint64_t mod_base = 0;
                        uint64_t pe = ios_jit_reverse_translate( state_rip_q, &mod_base );
                        static int leak_n;
                        if (pe && leak_n < 12)
                        {
                            uint64_t rsp = state.__x[23];  /* ARM64EC SRA: RSP=x23 */
                            uint64_t stk[8] = { 0 };
                            vm_size_t outsz = sizeof(stk);
                            leak_n++;
                            vm_read_overwrite( mach_task_self(), rsp, sizeof(stk),
                                               (vm_address_t)stk, &outsz );
                            dprintf(STDERR_FILENO,
                                "[rip-leak] guest RIP 0x%llx IS POOL addr = PE 0x%llx (module base 0x%llx rva 0x%llx)\n"
                                "[rip-leak] guest RSP=0x%llx stack: %llx %llx %llx %llx %llx %llx %llx %llx\n",
                                (unsigned long long)state_rip_q, (unsigned long long)pe,
                                (unsigned long long)mod_base,
                                (unsigned long long)(pe - mod_base),
                                (unsigned long long)rsp,
                                (unsigned long long)stk[0], (unsigned long long)stk[1],
                                (unsigned long long)stk[2], (unsigned long long)stk[3],
                                (unsigned long long)stk[4], (unsigned long long)stk[5],
                                (unsigned long long)stk[6], (unsigned long long)stk[7]);
                        }
                        /* task #34: reverse_translate returns 0 for a TOMBSTONED
                         * pool copy (owner cleared on unload/reclaim). That's the
                         * jsproxy-wall signature — the child pseudo-proc executing
                         * a pool copy its parent created and that's since been
                         * tombstoned. Name the owner directly so the parent/child
                         * ownership bug is unambiguous. */
                        if (!pe)
                        {
                            extern void *ios_jit_rx_base_global;
                            extern size_t ios_jit_pool_size_global;
                            extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                            uint64_t rx = (uint64_t)(uintptr_t)ios_jit_rx_base_global;
                            if (rx && state_rip_q >= rx && state_rip_q < rx + ios_jit_pool_size_global)
                            {
                                void *tpe = NULL;
                                void *towner = ios_jit_pool_copy_owner( (void *)(uintptr_t)state_rip_q, &tpe );
                                dprintf(STDERR_FILENO,
                                    "[rip-tomb] guest RIP 0x%llx in POOL (off 0x%llx) but NO live mapping — copy_owner=%p pe=%p (tombstoned/foreign pool copy; cross-ref [jit-pool] image name)\n",
                                    (unsigned long long)state_rip_q,
                                    (unsigned long long)(state_rip_q - rx),
                                    towner, tpe);
                            }
                        }
                    }
                }
                /* ml125: a runaway exec-fault storm hit 7.26 MILLION faults;
                 * at one line per 100 that alone wrote 72k lines and a 314k-line
                 * log, which costs device I/O and buries everything useful.
                 * After the first 200 reports the rate drops to 1-in-100000 —
                 * still enough to prove a storm is running and show where it
                 * ends, without the flood. terminal_pc always reports. */
                if (cnt <= 5 || terminal_pc ||
                    (cnt <= 20000 ? (cnt % 100) == 0 : (cnt % 100000) == 0))
                {
                    uint64_t fault_pc = fault_pc_check;
                    dprintf(STDERR_FILENO, "[mach_exc] UNHANDLED #%d pc=%p addr=%p x18=%p type=%d lr=%p sp=%p x16=%p x17=%p\n",
                        cnt, (void*)(uintptr_t)fault_pc, (void*)fault_addr,
                        (void*)(uintptr_t)state.__x[18], req->exception,
                        (void*)(uintptr_t)state.__lr,
                        (void*)(uintptr_t)__darwin_arm_thread_state64_get_sp(state),
                        (void*)(uintptr_t)state.__x[16],
                        (void*)(uintptr_t)state.__x[17]);
                    /* ml254: 4797 of 4832 faults share ONE call site
                     * (libarm64ecfex+0x1e8060: adrp/ldr x8,[x8,#0x38]/ldr x16,[x8]/blr x16
                     * -- an indirect call through a pointer-to-pointer, i.e. an import
                     * slot) and ONE target, x16=0x155ffc138: pool offset 0x37ffc138, the
                     * LAST page of the pool, in the trampoline region above the `used`
                     * cursor. Control reaches tiny, ODD-aligned PCs (0x22d1, 0x22d5) --
                     * odd is why bus_handler reports exec=1 -- so the tramp RAN and then
                     * branched to garbage. The same high band held the earlier CASPAL
                     * use-after-free (0x1541af700, MEM_FREE).
                     *
                     * Three candidate causes need different fixes: (a) tramp bytes are
                     * zero/garbage -- it was never written or was overwritten; (b) tramp
                     * is intact but its embedded target is stale -- a lifetime bug;
                     * (c) the page is gone (MEM_FREE / reclaimed / non-exec) -- a mapping
                     * bug. Only the bytes plus the region info discriminate, so dump both.
                     * Self-targeting (tiny pc + x16 in pool) so a storm cannot flood it. */
                    {
                        extern void *ios_jit_rx_base_global;
                        extern size_t ios_jit_pool_size_global;
                        uint64_t x16v = (uint64_t)state.__x[16];
                        uint64_t rxb  = (uint64_t)(uintptr_t)ios_jit_rx_base_global;
                        static int tramp_dumps;
                        /* ml255/ml256: the ORIGINAL condition also required x16 to be a
                         * pool address, which was fitted to ml254's signature
                         * (x16=0x155ffc138) rather than to the invariant. Two runs later
                         * x16 was 0x0 / 0x4000 / 0x1fffffff and the probe correctly but
                         * uselessly declined. The invariant is the tiny bogus pc; x16 is
                         * the thing we are trying to LEARN about, so it must not gate. */
                        if (fault_pc < 0x10000 && tramp_dumps < 6)
                        {
                            mach_vm_address_t qa = (mach_vm_address_t)(x16v & ~0x3fffull);
                            mach_vm_size_t qs = 0;
                            vm_region_extended_info_data_t qi;
                            mach_msg_type_number_t qc = VM_REGION_EXTENDED_INFO_COUNT;
                            mach_port_t qo = MACH_PORT_NULL;
                            kern_return_t qkr;
                            /* extended info carries share_mode/user_tag but NOT
                             * max_protection; basic_64 carries max. Need both, and
                             * max is the one that says "can never be exec again". */
                            mach_vm_address_t ba = qa;
                            mach_vm_size_t bs = 0;
                            vm_region_basic_info_data_64_t bi;
                            mach_msg_type_number_t bc = VM_REGION_BASIC_INFO_COUNT_64;
                            mach_port_t bo = MACH_PORT_NULL;
                            int bmax = -1;

                            tramp_dumps++;
                            if (mach_vm_region( mach_task_self(), &ba, &bs,
                                                VM_REGION_BASIC_INFO_64,
                                                (vm_region_info_t)&bi, &bc, &bo ) == KERN_SUCCESS
                                && ba <= (x16v & ~0x3fffull))
                                bmax = bi.max_protection;
                            qkr = mach_vm_region( mach_task_self(), &qa, &qs,
                                                  VM_REGION_EXTENDED_INFO,
                                                  (vm_region_info_t)&qi, &qc, &qo );
                            if (qkr == KERN_SUCCESS && qa <= (x16v & ~0x3fffull))
                                dprintf(STDERR_FILENO,
                                    "[tramp-dump] x16=0x%llx pooloff=0x%llx REGION base=0x%llx size=0x%llx "
                                    "prot=0x%x max=0x%x share=%d tag=%d\n",
                                    (unsigned long long)x16v,
                                    (unsigned long long)(rxb ? x16v - rxb : 0),
                                    (unsigned long long)qa, (unsigned long long)qs,
                                    qi.protection, bmax,
                                    qi.share_mode, qi.user_tag);
                            else
                                dprintf(STDERR_FILENO,
                                    "[tramp-dump] x16=0x%llx pooloff=0x%llx REGION **NONE** (kr=%d, first region above = 0x%llx) "
                                    "-- page is NOT MAPPED\n",
                                    (unsigned long long)x16v,
                                    (unsigned long long)(rxb ? x16v - rxb : 0),
                                    qkr, (unsigned long long)qa);

                            /* the tramp's own words -- only if the page is readable */
                            if (qkr == KERN_SUCCESS && qa <= (x16v & ~0x3fffull) &&
                                (qi.protection & VM_PROT_READ))
                            {
                                const uint32_t *w = (const uint32_t *)(uintptr_t)x16v;
                                dprintf(STDERR_FILENO,
                                    "[tramp-dump]   words: %08x %08x %08x %08x %08x %08x\n",
                                    w[0], w[1], w[2], w[3], w[4], w[5]);
                            }
                        }
                    }
                    /* ml224: name the faulting address against the JIT-pool ledger.
                     *
                     * Steam/CEF dies on a 128-bit atomic whose target VirtualQuery
                     * reports MEM_FREE while sitting INSIDE the pool's span -- so the
                     * pointer is dangling, not misaligned, and pool lifetime is the
                     * suspect. Whether the range is on the reclaim freelist, still a live
                     * mapping, or neither picks between three different fixes, and this
                     * is the only place that can tell. Rate-limited with the dump it
                     * rides on, so a fault storm cannot flood the log. */
                    {
                        extern void ios_jit_describe_pool_addr( const void *addr, char *buf,
                                                                size_t buflen );
                        static int ledger_n;
                        char pooldesc[192];

                        /* ml225: riding the mach_exc limiter alone still produced 3790
                         * lines in one run, because a null-deref storm (addr=0x10/0xc/0x2)
                         * asks the ledger a question it can only answer "OUTSIDE pool".
                         * Only sub-pool-band addresses are interesting here, and cap the
                         * rest, so the interesting verdict cannot be buried. */
                        if (ledger_n < 40 && fault_addr >= 0x10000)
                        {
                            ledger_n++;
                            ios_jit_describe_pool_addr( (const void *)fault_addr, pooldesc,
                                                        sizeof(pooldesc) );
                            dprintf( STDERR_FILENO, "[mach_exc]   [pool-ledger] addr=%p : %s\n",
                                     (void *)fault_addr, pooldesc );
                        }
                    }
                    /* ml226: is the guest RSP TRUNCATED TO 32 BITS, or already garbage?
                     *
                     * The recurring fatal address family is 0x40001141 / 0x80001141 /
                     * 0xe0001141 -- all 32-bit values with identical low halves, reached
                     * through a guest PUSH (ldr x2,[x28,#0x40]; sub x2,x2,#0x10; str x0,[x2]).
                     * A 64-bit RSP does not look like that. One reading is an instruction
                     * writing RSP with 32-bit operand size (mov esp,eax semantics), which
                     * would be a FEX decode bug; the other is that RSP arrived corrupt from
                     * somewhere upstream, which is a different bug entirely.
                     *
                     * Decide it by dumping the guest state and the x86 bytes AT the guest
                     * RIP. If those bytes decode to a 32-bit write to RSP the first reading
                     * is confirmed; if they are an ordinary push/call then RSP was already
                     * wrong on entry and the truncation idea is dead. Prints the raw bytes
                     * rather than a verdict so it can say "neither". */
                    {
                        static int rsp_n;
                        uint64_t st28 = state.__x[28];
                        uint64_t cs[5];            /* +0x18 rip .. +0x38 */
                        uint64_t rsp = 0;
                        unsigned char code[16];
                        mach_vm_size_t g = 0;

                        if (rsp_n < 12 && st28 > 0x100000 &&
                            mach_vm_read_overwrite( mach_task_self(),
                                (mach_vm_address_t)(st28 + 0x18), sizeof(cs),
                                (mach_vm_address_t)cs, &g ) == KERN_SUCCESS && g == sizeof(cs) &&
                            mach_vm_read_overwrite( mach_task_self(),
                                (mach_vm_address_t)(st28 + 0x40), 8,
                                (mach_vm_address_t)&rsp, &g ) == KERN_SUCCESS)
                        {
                            rsp_n++;
                            dprintf( STDERR_FILENO,
                                     "[rsp-trunc] x28=%p guest_rip=%p rsp=%p rsp_hi32=%s\n",
                                     (void *)st28, (void *)cs[0], (void *)rsp,
                                     (rsp >> 32) ? "set (64-bit)" : "ZERO (looks truncated)" );
                            g = 0;
                            if (cs[0] && mach_vm_read_overwrite( mach_task_self(),
                                    (mach_vm_address_t)cs[0], sizeof(code),
                                    (mach_vm_address_t)code, &g ) == KERN_SUCCESS &&
                                g == sizeof(code))
                                dprintf( STDERR_FILENO,
                                         "[rsp-trunc]   x86 @rip: %02x %02x %02x %02x %02x %02x %02x %02x"
                                         " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                         code[0],code[1],code[2],code[3],code[4],code[5],code[6],code[7],
                                         code[8],code[9],code[10],code[11],code[12],code[13],code[14],code[15] );
                            else
                                dprintf( STDERR_FILENO, "[rsp-trunc]   x86 @rip UNREADABLE\n" );
                        }
                    }
                    /* [ec-fault-regs] the faulting insn f8686928 = ldr x8,[x9,x8]:
                     * addr = x9(base) + x8(index). Dump x8..x11 so we can name the
                     * table (EC bitmap? syscall-frame? LookupCache?) and why it's bad. */
                    if (cnt <= 3)
                    {
                        void *peb_ecbm = NULL; void *peb_p = NULL;
                        if (thread_teb) {
                            peb_p = ((TEB *)thread_teb)->Peb;
                            /* PEB->EcCodeBitMap read DIRECTLY (same struct is_ec_code
                             * uses). If this != 0 but x9==0, is_ec_code read a wrong
                             * offset / wrong peb; if this == 0, the field is really null
                             * for this thread's peb (timing / peb not wired). */
                            if (peb_p) peb_ecbm = ((PEB *)peb_p)->EcCodeBitMap;
                        }
                        dprintf(STDERR_FILENO, "[ec-fault-regs] x8=%p x9=%p x10=%p x11=%p x0=%p x2=%p | teb=%p peb=%p peb->EcCodeBitMap=%p\n",
                            (void*)(uintptr_t)state.__x[8], (void*)(uintptr_t)state.__x[9],
                            (void*)(uintptr_t)state.__x[10], (void*)(uintptr_t)state.__x[11],
                            (void*)(uintptr_t)state.__x[0], (void*)(uintptr_t)state.__x[2],
                            (void *)thread_teb, peb_p, peb_ecbm);
                    }
                    /* Read instruction at LR-4 to identify the BL/BLR */
                    if (cnt <= 3 && (uintptr_t)state.__lr >= 0x100000000ULL)
                    {
                        uint32_t *lr_p = (uint32_t*)(uintptr_t)(state.__lr - 4);
                        dprintf(STDERR_FILENO, "[mach_exc] caller_insn @lr-4=0x%p: 0x%08x\n",
                            (void*)lr_p, *lr_p);
                    }
                    /* Which pool COPY is pc in, and who owns it? Names the
                     * session-vs-child copy — the PE attribution below can't
                     * (all copies share PE VAs). owner=-1 = not pool. */
                    {
                        extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                        void *copy_pe = NULL;
                        void *copy_owner = ios_jit_pool_copy_owner((void *)(uintptr_t)fault_pc, &copy_pe);
                        void *cur_teb_peb = thread_teb ? ((TEB *)thread_teb)->Peb : NULL;
                        dprintf(STDERR_FILENO,
                            "[mach_exc] pc pool-copy pe=%p owner=%p; thread teb=%p peb=%p\n",
                            copy_pe, copy_owner, (void *)thread_teb, cur_teb_peb);
                        /* [nls-probe] The first fault is upcase_unicode_to_utf8 (ntdll RVA
                         * 0x38aa8) reading the NLS upcase-table pointer at ntdll .data RVA
                         * 0xc04e0 via `adrp x16,0xc0000; ldr x7,[x16,#0x4e0]` — and getting
                         * NULL. Compare the value the POOL copy read (x16+0x4e0) against the
                         * PE mapping's own .data (copy_pe+0xc04e0). If PE!=0 && pool==0 the
                         * pool copy's .data is stale (fix = sync/share ntdll .data); if both
                         * 0 the PE global was never populated (fix is upstream NLS init). */
                        if (cnt <= 2 && copy_pe && (uintptr_t)copy_pe >= 0x100000000ULL)
                        {
                            uint64_t x16v = (uint64_t)state.__x[16];
                            uint64_t pool_v = (x16v >= 0x100000000ULL)
                                ? *(volatile uint64_t *)(uintptr_t)(x16v + 0x4e0) : 0xdead1;
                            uint64_t pe_v = *(volatile uint64_t *)((uintptr_t)copy_pe + 0xc04e0);
                            dprintf(STDERR_FILENO,
                                "[nls-probe] upcase ptr: pool[x16+0x4e0]=0x%llx  PE[pe+0xc04e0]=0x%llx  (x16=0x%llx pe=%p rva_pc=0x%llx)\n",
                                (unsigned long long)pool_v, (unsigned long long)pe_v,
                                (unsigned long long)x16v, copy_pe,
                                (unsigned long long)((uintptr_t)fault_pc - ((uintptr_t)fault_pc & ~0xfffffULL)));
                        }
                    }
                    if ((uintptr_t)fault_pc >= 0x100000000ULL)
                    {
                        uint32_t *p = (uint32_t*)(uintptr_t)fault_pc;
                        dprintf(STDERR_FILENO, "[mach_exc] insn_stream PC-12..PC+8: %08x %08x %08x [%08x] %08x %08x %08x\n",
                            p[-3], p[-2], p[-1], p[0], p[1], p[2], p[3]);
                    }
                    /* iOS-Mythic: symbolize pc/lr via dladdr — works for
                     * dyld-cache addresses in-process. Names the native
                     * subsystem when a fault lands in system frameworks
                     * (e.g. the 2026-07-04 post-UNIXCALL-DIRECT crash at
                     * 0x18521c0d0 was unattributable offline: DeviceSupport
                     * symbol tree only has lazily-extracted dylibs). */
                    {
                        Dl_info di_pc, di_lr;
                        const char *pc_img = "?", *pc_sym = "?"; uint64_t pc_off = 0;
                        const char *lr_img = "?", *lr_sym = "?"; uint64_t lr_off = 0;
                        if (dladdr((void*)(uintptr_t)fault_pc, &di_pc))
                        {
                            if (di_pc.dli_fname) pc_img = di_pc.dli_fname;
                            if (di_pc.dli_sname) { pc_sym = di_pc.dli_sname;
                                pc_off = fault_pc - (uint64_t)(uintptr_t)di_pc.dli_saddr; }
                        }
                        if (dladdr((void*)(uintptr_t)state.__lr, &di_lr))
                        {
                            if (di_lr.dli_fname) lr_img = di_lr.dli_fname;
                            if (di_lr.dli_sname) { lr_sym = di_lr.dli_sname;
                                lr_off = state.__lr - (uint64_t)(uintptr_t)di_lr.dli_saddr; }
                        }
                        dprintf(STDERR_FILENO,
                            "[mach_exc] sym pc=%s`%s+0x%llx lr=%s`%s+0x%llx\n",
                            pc_img, pc_sym, (unsigned long long)pc_off,
                            lr_img, lr_sym, (unsigned long long)lr_off);
                        /* JIT-pool addresses: name the PE module + offset
                         * (same machinery as [thread-stacks]) so faults in
                         * copied PE code self-symbolize. */
                        {
                            extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                            uint64_t mod, va;
                            if ((va = ios_jit_reverse_translate( fault_pc, &mod )))
                                dprintf(STDERR_FILENO, "[mach_exc] pc PE: %s+0x%llx (va=0x%llx)\n",
                                        ios_pe_module_name(mod), (unsigned long long)(va - mod),
                                        (unsigned long long)va);
                            /* [bucketscan-probe] Thumper dies in FEXCore GuestToHostMap::BlockList
                             * (ankerl unordered_dense) do_find (libarm64ecfex ~RVA 0x1d140-0x1d280,
                             * caller LookupCache::FindBlock) scanning its bucket array OFF THE END:
                             * loop `add x17,x11,w12,uxtw#3; ldr w1,[x17]` => x11=buckets base,
                             * w12=index, x17=x11+w12*8 walks unmapped guest mem. Dump base/index/
                             * scan-distance/key (NO deref — stay signal-safe) to tell UNINITIALIZED
                             * (x11 garbage/tiny, no valid array) from TORN-READ (x11 a valid heap
                             * ptr but distance huge => bounds/mask stale from a concurrent swap). */
                            {
                                uint64_t bs_mod, bs_va;
                                if ((bs_va = ios_jit_reverse_translate( fault_pc, &bs_mod )))
                                {
                                    uint64_t bs_rva = bs_va - bs_mod;
                                    /* [findblock-probe] LookupCache::FindBlock(x0=this=LookupCache*, x1=Thread,
                                     * x2=Address). Its L1 lookup faults at ~0x18c90: ldp x8,x9,[x0,#0x30] (x0[0x30]=
                                     * L1 base, x0[0x38]=L1 mask), x25=x8+(x9&x2)<<4, ldr [x25]. Capture x0 (the LIVE
                                     * LookupCache ptr — dead by do_find) + L1 fields to tell a BOGUS x0 (garbage/
                                     * guest ptr from the dispatcher/StateFrame) from a valid-but-corrupted cache. */
                                    if (bs_rva >= 0x18c70 && bs_rva < 0x18e20)
                                    {
                                        static volatile int fb_seen = 0;
                                        if (__sync_fetch_and_add(&fb_seen, 1) < 6)
                                        {
                                            uint64_t x0v = (uint64_t)state.__x[0];
                                            uint64_t l1base = 0xdead, l1mask = 0xdead;
                                            int host = (x0v >= 0x100000000ULL && x0v < 0x800000000000ULL);
                                            if (host) {
                                                l1base = *(volatile uint64_t *)(uintptr_t)(x0v + 0x30);
                                                l1mask = *(volatile uint64_t *)(uintptr_t)(x0v + 0x38);
                                            }
                                            dprintf(STDERR_FILENO,
                                                "[findblock-probe] rva=0x%llx x0(LookupCache)=0x%llx host=%d x1(Thread)=0x%llx x2(rip)=0x%llx L1base[0x30]=0x%llx L1mask[0x38]=0x%llx\n",
                                                (unsigned long long)bs_rva, (unsigned long long)x0v, host,
                                                (unsigned long long)state.__x[1], (unsigned long long)state.__x[2],
                                                (unsigned long long)l1base, (unsigned long long)l1mask);
                                        }
                                    }
                                    if (bs_rva >= 0x1d100 && bs_rva < 0x1d300)
                                    {
                                        static volatile int bs_seen = 0;
                                        if (__sync_fetch_and_add(&bs_seen, 1) < 6)
                                        {
                                            uint64_t x8v  = (uint64_t)state.__x[8];
                                            uint64_t x11v = (uint64_t)state.__x[11];
                                            uint64_t x12v = (uint64_t)state.__x[12];
                                            uint64_t x15v = (uint64_t)state.__x[15];
                                            uint64_t x17v = (uint64_t)state.__x[17];
                                            dprintf(STDERR_FILENO,
                                                "[bucketscan-probe] do_find rva=0x%llx x11(base)=0x%llx x17(cur)=0x%llx scan_dist=0x%llx(%llu buckets) x8=0x%llx x12(idx)=0x%llx x15(key)=0x%llx\n",
                                                (unsigned long long)bs_rva, (unsigned long long)x11v,
                                                (unsigned long long)x17v, (unsigned long long)(x17v - x11v),
                                                (unsigned long long)((x17v - x11v) / 8), (unsigned long long)x8v,
                                                (unsigned long long)x12v, (unsigned long long)x15v);
                                            /* Dump the actual bucket CONTENTS at x11 (m_buckets). This range is
                                             * mapped (the scan reads it up to x17). Each ankerl bucket = 8 bytes
                                             * {u32 dist_and_fingerprint, u32 value_idx}. All-zero => empty (do_find
                                             * would have stopped); small ascending d_a_f => a real map; random
                                             * huge values => uninitialized/torn/UAF backing store. Also dump
                                             * callee-saved regs so we can recover `this` (do_find: this[0x18]==
                                             * m_buckets, this[0x3e]=m_shifts) offline. */
                                            {
                                                uint64_t bk[6] = {0,0,0,0,0,0};
                                                if (x11v >= 0x100000000ULL && x11v < 0x800000000000ULL)
                                                    for (int bi = 0; bi < 6; bi++)
                                                        bk[bi] = *(volatile uint64_t *)(uintptr_t)(x11v + (uint64_t)bi * 8);
                                                dprintf(STDERR_FILENO,
                                                    "[bucketscan-probe] buckets@x11: %016llx %016llx %016llx %016llx %016llx %016llx | x0=%llx x9=%llx x10=%llx x19=%llx x20=%llx x21=%llx x22=%llx\n",
                                                    (unsigned long long)bk[0], (unsigned long long)bk[1],
                                                    (unsigned long long)bk[2], (unsigned long long)bk[3],
                                                    (unsigned long long)bk[4], (unsigned long long)bk[5],
                                                    (unsigned long long)state.__x[0], (unsigned long long)state.__x[9],
                                                    (unsigned long long)state.__x[10], (unsigned long long)state.__x[19],
                                                    (unsigned long long)state.__x[20], (unsigned long long)state.__x[21],
                                                    (unsigned long long)state.__x[22]);
                                                /* Recover the map `this`: do_find has this[0x18]==m_buckets(x11v).
                                                 * Whichever candidate reg, at +0x18, holds x11v is `this`. Then dump
                                                 * its ankerl fields to tell a real-but-corrupted map (sane values
                                                 * ptrs, only m_buckets bad) from a wrong/guest `this`. Guarded reads. */
                                                {
                                                    uint64_t cands[4] = { (uint64_t)state.__x[10], (uint64_t)state.__x[19],
                                                                          (uint64_t)state.__x[21], (uint64_t)state.__x[0] };
                                                    int found = 0;
                                                    for (int ci = 0; ci < 4 && !found; ci++) {
                                                        uint64_t th = cands[ci];
                                                        if (th < 0x100000000ULL || th >= 0x800000000000ULL) continue;
                                                        uint64_t mb = *(volatile uint64_t *)(uintptr_t)(th + 0x18);
                                                        if (mb != x11v) continue;
                                                        found = 1;
                                                        uint64_t vb  = *(volatile uint64_t *)(uintptr_t)(th + 0x0);
                                                        uint64_t ve  = *(volatile uint64_t *)(uintptr_t)(th + 0x8);
                                                        uint64_t f20 = *(volatile uint64_t *)(uintptr_t)(th + 0x20);
                                                        uint64_t f28 = *(volatile uint64_t *)(uintptr_t)(th + 0x28);
                                                        uint8_t  sh  = *(volatile uint8_t  *)(uintptr_t)(th + 0x3e);
                                                        dprintf(STDERR_FILENO,
                                                            "[bucketscan-probe] THIS=0x%llx(reg%d) values.begin=0x%llx end=0x%llx [0x20]=0x%llx [0x28]=0x%llx m_shifts=0x%x\n",
                                                            (unsigned long long)th, ci, (unsigned long long)vb,
                                                            (unsigned long long)ve, (unsigned long long)f20,
                                                            (unsigned long long)f28, sh);
                                                    }
                                                    if (!found)
                                                        dprintf(STDERR_FILENO,
                                                            "[bucketscan-probe] THIS not found in x0/x10/x19/x21 (map ptr not in loop regs)\n");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if ((va = ios_jit_reverse_translate( state.__lr, &mod )))
                                dprintf(STDERR_FILENO, "[mach_exc] lr PE: %s+0x%llx (va=0x%llx)\n",
                                        ios_pe_module_name(mod), (unsigned long long)(va - mod),
                                        (unsigned long long)va);
                            /* [nullfp-probe] When the fault is #arm64x_check_call with x11=0,
                             * the EC indirect-call TARGET is null. The caller pattern is
                             *   lr-0x1c: adrp xN, PAGE ;  lr-0xc: ldr x11,[xN,#OFF] ;  lr-4: blr x8
                             * Decode adrp+ldr to recover the target-global address, then read it
                             * from BOTH the pool COPY and the PE mapping. pool==0 && PE!=0 => the
                             * pool copy's .data was never relocated/synced (same class as the NLS
                             * casemap bug); both==0 => the static-init that populates it never ran. */
                            if (cnt <= 3 && va && (uintptr_t)state.__x[11] == 0 &&
                                (uintptr_t)state.__lr >= 0x100000000ULL)
                            {
                                uint64_t lr_rva = va - mod;
                                uint64_t pool_base = (uint64_t)state.__lr - lr_rva;
                                uint32_t *cp = (uint32_t *)(uintptr_t)state.__lr;
                                uint32_t adrp_i = cp[-7];   /* lr-0x1c */
                                uint32_t ldr_i  = cp[-3];   /* lr-0xc  */
                                int is_adrp = ((adrp_i >> 24) & 0x9f) == 0x90;
                                int is_ldr  = ((ldr_i  >> 22) & 0x3ff) == 0x3e5; /* LDR imm,64 unsigned */
                                if (is_adrp && is_ldr)
                                {
                                    int64_t immlo = (adrp_i >> 29) & 0x3;
                                    int64_t immhi = (adrp_i >> 5) & 0x7ffff;
                                    int64_t imm = (immhi << 2) | immlo;
                                    if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
                                    uint64_t adrp_pc = (uint64_t)state.__lr - 0x1c;
                                    uint64_t page = (adrp_pc & ~0xfffULL) + ((uint64_t)imm << 12);
                                    uint64_t off  = (uint64_t)((ldr_i >> 10) & 0xfff) << 3;
                                    uint64_t g_pool = page + off;
                                    uint64_t g_rva  = g_pool - pool_base;
                                    uint64_t gv_pool = *(volatile uint64_t *)(uintptr_t)g_pool;
                                    uint64_t gv_pe   = *(volatile uint64_t *)(uintptr_t)(mod + g_rva);
                                    dprintf(STDERR_FILENO,
                                        "[nullfp-probe] tgt-global rva=0x%llx pool[0x%llx]=0x%llx PE[0x%llx]=0x%llx mod=%s lr_rva=0x%llx\n",
                                        (unsigned long long)g_rva,
                                        (unsigned long long)g_pool, (unsigned long long)gv_pool,
                                        (unsigned long long)(mod + g_rva), (unsigned long long)gv_pe,
                                        ios_pe_module_name(mod), (unsigned long long)lr_rva);
                                }
                                else
                                    dprintf(STDERR_FILENO,
                                        "[nullfp-probe] caller not adrp+ldr: adrp_i=0x%08x ldr_i=0x%08x lr_rva=0x%llx mod=%s\n",
                                        adrp_i, ldr_i, (unsigned long long)(va - mod), ios_pe_module_name(mod));
                            }
                        }
                        /* fp-chain backtrace of the faulting thread — names
                         * the exact native call path (which Metal call fed
                         * free() a garbage pointer). Native code has honest
                         * x29 chains; stop on invalid fp. */
                        if (cnt <= 3)
                        {
                            uint64_t fp_walk = state.__fp;
                            int fr;
                            for (fr = 0; fr < 10 && fp_walk; fr++)
                            {
                                uint64_t frame_buf[2];
                                mach_vm_size_t got_fw = 0;
                                if (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)fp_walk, 16,
                                        (mach_vm_address_t)frame_buf, &got_fw)
                                        != KERN_SUCCESS || got_fw != 16)
                                    break;
                                {
                                    uint64_t ret_pc = frame_buf[1];
                                    Dl_info di_f;
                                    const char *f_img = "?", *f_sym = "?";
                                    uint64_t f_off = ret_pc;
                                    if (ret_pc > 0x4000 &&
                                        dladdr((void*)(uintptr_t)ret_pc, &di_f))
                                    {
                                        if (di_f.dli_fname) f_img = di_f.dli_fname;
                                        if (di_f.dli_sname) { f_sym = di_f.dli_sname;
                                            f_off = ret_pc - (uint64_t)(uintptr_t)di_f.dli_saddr; }
                                    }
                                    dprintf(STDERR_FILENO,
                                        "[mach_exc] bt[%d] 0x%llx %s`%s+0x%llx\n",
                                        fr, (unsigned long long)ret_pc,
                                        f_img, f_sym, (unsigned long long)f_off);
                                    if (ret_pc <= 0x4000) break;
                                }
                                fp_walk = frame_buf[0];
                            }
                        }
                        /* Stack scan ([term-stack] pattern): the exit-path
                         * crashers have no walkable fp chain, so reconstruct
                         * call history from return addresses left on the
                         * stack. Copy attribution per hit — the frame where
                         * copy_owner flips from a child peb to 0 (session)
                         * is where the thread crossed ntdll copies. */
                        if (cnt <= 3)
                        {
                            extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                            extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                            uint64_t sp_scan = __darwin_arm_thread_state64_get_sp(state);
                            int w2, hits = 0;
                            for (w2 = 0; w2 < 512 && hits < 24; w2++)
                            {
                                uint64_t slot_val;
                                mach_vm_size_t got_sv = 0;
                                if (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)(sp_scan + 8ull * w2), 8,
                                        (mach_vm_address_t)&slot_val, &got_sv)
                                        != KERN_SUCCESS || got_sv != 8)
                                    break;
                                {
                                    uint64_t mod3, va3;
                                    if ((va3 = ios_jit_reverse_translate( slot_val, &mod3 )) && va3 != slot_val)
                                    {
                                        void *cp3 = NULL;
                                        void *co3 = ios_jit_pool_copy_owner((void *)(uintptr_t)slot_val, &cp3);
                                        dprintf(STDERR_FILENO,
                                            "[exit-stk] sp+0x%x: 0x%llx = %s+0x%llx copy_owner=%p\n",
                                            w2 * 8, (unsigned long long)slot_val,
                                            ios_pe_module_name(mod3),
                                            (unsigned long long)(va3 - mod3), co3);
                                        hits++;
                                    }
                                }
                            }
                        }
                        /* One-shot: dump the faulting native function's
                         * prologue so we can see what per-thread/global
                         * state it reads (libsystem_malloc keeps dying on
                         * corrupt zone state — need its actual fastpath). */
                        static volatile int proto_dumped = 0;
                        if (di_pc.dli_saddr && fault_pc >= 0x180000000ULL &&
                            __sync_bool_compare_and_swap(&proto_dumped, 0, 1))
                        {
                            uint32_t *fp = (uint32_t*)di_pc.dli_saddr;
                            int w;
                            for (w = 0; w < 40; w += 8)
                                dprintf(STDERR_FILENO,
                                    "[mach_exc] fn+%03x: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                                    w * 4, fp[w], fp[w+1], fp[w+2], fp[w+3],
                                    fp[w+4], fp[w+5], fp[w+6], fp[w+7]);
                        }
                    }
                    /* Thing B one-shot: a zero-page pc crawl means a thread
                     * took `blr x16` with x16==1 from an EC exit thunk
                     * ($iexit_thunk$ at EC ntdll+0x73040: adrp x8,+0x51
                     * pages; ldr x16,[x8,#0x480]; blr x16). Dump (a) the
                     * ARM64X dispatch slots of every private EC ntdll copy,
                     * (b) the qword the adrp ACTUALLY dereferenced computed
                     * from the execution-address lr (catches link-vs-exec
                     * address skew in pool copies), (c) x9 — exit-thunk
                     * convention: x9 = the x64 target being called — and
                     * (d) an fp-chain backtrace with PE attribution so the
                     * call path INTO the thunk names itself. */
                    static volatile int thunk_probe_shots = 0;
                    if (fault_pc < 0x1000 && thunk_probe_shots < 3)
                    {
                        extern void ios_dump_ec_dispatch_slots( unsigned long long lr_va, unsigned long long x9 );
                        extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                        uint64_t lr_exec = state.__lr & 0x0000007fffffffffull;
                        uint64_t lr_mod = 0, lr_va = ios_jit_reverse_translate( lr_exec, &lr_mod );
                        uint64_t fp_walk;
                        int fr;
                        __sync_add_and_fetch(&thunk_probe_shots, 1);
                        dprintf(STDERR_FILENO,
                            "[thunk-slot] WEDGE pc=0x%llx lr_exec=0x%llx lr_va=0x%llx (%.32s) "
                            "x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx "
                            "x8=0x%llx x9=0x%llx x10=0x%llx x11=0x%llx fp=0x%llx\n",
                            (unsigned long long)fault_pc,
                            (unsigned long long)lr_exec, (unsigned long long)lr_va,
                            lr_mod ? ios_pe_module_name(lr_mod) : "?",
                            (unsigned long long)state.__x[0], (unsigned long long)state.__x[1],
                            (unsigned long long)state.__x[2], (unsigned long long)state.__x[3],
                            (unsigned long long)state.__x[4], (unsigned long long)state.__x[8],
                            (unsigned long long)state.__x[9], (unsigned long long)state.__x[10],
                            (unsigned long long)state.__x[11], (unsigned long long)state.__fp);
                        ios_dump_ec_dispatch_slots( lr_va ? lr_va : lr_exec,
                                                    state.__x[9] );
                        /* Exec-relative adrp target: adrp sits at lr-0xc;
                         * its immediate is +0x51 pages, ldr offset 0x480
                         * (fixed by the thunk's encoding — see disasm of
                         * arm64ec-windows/ntdll.dll +0x73048). */
                        {
                            uint64_t adrp_tgt = ((lr_exec - 0xc) & ~0xFFFULL) + 0x51000 + 0x480;
                            uint64_t slot_val = 0;
                            mach_vm_size_t got_sv = 0;
                            if (mach_vm_read_overwrite(mach_task_self(),
                                    (mach_vm_address_t)adrp_tgt, 8,
                                    (mach_vm_address_t)&slot_val, &got_sv) == KERN_SUCCESS && got_sv == 8)
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] exec-relative slot @0x%llx = 0x%llx\n",
                                    (unsigned long long)adrp_tgt, (unsigned long long)slot_val);
                            else
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] exec-relative slot @0x%llx UNREADABLE\n",
                                    (unsigned long long)adrp_tgt);
                        }
                        fp_walk = state.__fp;
                        for (fr = 0; fr < 16 && fp_walk; fr++)
                        {
                            uint64_t frame_buf[2];
                            mach_vm_size_t got_fw = 0;
                            uint64_t ret_pc, bt_mod, bt_va;
                            if (mach_vm_read_overwrite(mach_task_self(),
                                    (mach_vm_address_t)fp_walk, 16,
                                    (mach_vm_address_t)frame_buf, &got_fw) != KERN_SUCCESS || got_fw != 16)
                                break;
                            ret_pc = frame_buf[1] & 0x0000007fffffffffull;
                            if (ret_pc <= 0x4000) break;
                            bt_mod = 0;
                            bt_va = ios_jit_reverse_translate( ret_pc, &bt_mod );
                            if (bt_va)
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] bt[%d] 0x%llx PE %.32s+0x%llx (base=0x%llx)\n",
                                    fr, (unsigned long long)ret_pc,
                                    ios_pe_module_name(bt_mod),
                                    (unsigned long long)(bt_va - bt_mod),
                                    (unsigned long long)bt_mod);
                            else
                            {
                                Dl_info di_t;
                                const char *t_img = "?", *t_sym = "?";
                                uint64_t t_off = ret_pc;
                                if (dladdr((void*)(uintptr_t)ret_pc, &di_t))
                                {
                                    if (di_t.dli_fname) { t_img = strrchr(di_t.dli_fname, '/'); t_img = t_img ? t_img + 1 : di_t.dli_fname; }
                                    if (di_t.dli_sname) { t_sym = di_t.dli_sname; t_off = ret_pc - (uint64_t)(uintptr_t)di_t.dli_saddr; }
                                }
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] bt[%d] 0x%llx %s`%s+0x%llx\n",
                                    fr, (unsigned long long)ret_pc, t_img, t_sym,
                                    (unsigned long long)t_off);
                            }
                            fp_walk = frame_buf[0];
                        }
                    }
                    /* One-shot dump: on the first UNHANDLED exec fault, dump the
                     * JIT-pool RW alias contents around the relevant FEX CodeBuffer
                     * slots to a file. Lets us disassemble FEX-emitted ARM64 offline
                     * to verify codegen correctness independently. */
                    static volatile int dumped = 0;
                    if (cnt == 1 && __sync_bool_compare_and_swap(&dumped, 0, 1))
                    {
                        extern void *ios_jit_rw_base_global;
                        extern size_t ios_jit_pool_size_global;
                        if (ios_jit_rw_base_global && ios_jit_pool_size_global)
                        {
                            const char *docs = getenv("MYTHIC_DOCS_DIR");
                            char path[512];
                            if (docs)
                                snprintf(path, sizeof(path), "%s/fex-jit-dump.bin", docs);
                            else
                                snprintf(path, sizeof(path), "/tmp/fex-jit-dump.bin");
                            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                            if (fd >= 0)
                            {
                                /* Dump the entire JIT pool RW alias. ~128MB but
                                 * mostly zero. Compresses well; helpful to scan
                                 * any populated region. */
                                ssize_t off = 0;
                                size_t total = ios_jit_pool_size_global;
                                while ((size_t)off < total)
                                {
                                    ssize_t n = write(fd, (char*)ios_jit_rw_base_global + off,
                                                       total - off > 0x10000 ? 0x10000 : total - off);
                                    if (n <= 0) break;
                                    off += n;
                                }
                                close(fd);
                                dprintf(STDERR_FILENO, "[mach_exc] DUMPED JIT pool RW alias (%zd bytes) to %s\n", off, path);
                            }
                            else
                            {
                                dprintf(STDERR_FILENO, "[mach_exc] DUMP open failed errno=%d path=%s\n", errno, path);
                            }
                        }
                    }
                    /* Diagnostic: query the kernel for what VM region the fault PC lives in.
                     * Helps identify mystery regions (e.g. JIT pool guard zone, wineserver heap). */
                    if (cnt <= 3)
                    {
                        mach_vm_address_t qa = (mach_vm_address_t)fault_pc;
                        mach_vm_size_t qs = 0;
                        vm_region_basic_info_data_64_t qinfo;
                        mach_msg_type_number_t qcnt = VM_REGION_BASIC_INFO_COUNT_64;
                        mach_port_t qobj = MACH_PORT_NULL;
                        if (mach_vm_region(mach_task_self(), &qa, &qs,
                                           VM_REGION_BASIC_INFO_64,
                                           (vm_region_info_t)&qinfo, &qcnt, &qobj)
                            == KERN_SUCCESS)
                        {
                            dprintf(STDERR_FILENO,
                                "[mach_exc] vm_region: addr=0x%llx size=0x%llx prot=0x%x max_prot=0x%x inherit=%d shared=%d offset=0x%llx\n",
                                (unsigned long long)qa, (unsigned long long)qs,
                                qinfo.protection, qinfo.max_protection,
                                qinfo.inheritance, qinfo.shared,
                                (unsigned long long)qinfo.offset);
                        }
                    }

                    /* iOS-Mythic: dump x86 STATE on the first few faults. FEX rarely
                     * spills RSP/RSI/RDI etc to State.gregs[] (they live in static
                     * ARM regs x23/x25/x26 and only get spilled at SpillStaticRegs
                     * call sites — which most of __dyn_tls_init's path never hits).
                     * So the LIVE x86 register values are in state.__x[] of the
                     * faulted thread. ARM64EC SRA:
                     *   RAX=x8, RCX=x0 (pair0); RDX=x1, RBX=x27 (pair1);
                     *   RSP=x23, RBP=x29 (pair2); RSI=x25, RDI=x26 (pair3);
                     *   R8=x2, R9=x3, R10=x4, R11=x5; R12=x19, R13=x20, R14=x21, R15=x22.
                     * State pointer is reachable via TEB+0x1788 -> CPUArea+0x30.   */
                    /* Read State.RIP unconditionally so we can decide whether
                     * this fault is "interesting" (i.e., in known Thumper DXGI
                     * dispatch range 0x140079xxx-0x14007axxx). Dump full state
                     * for first 3 faults OR any interesting RIP. */
                    uintptr_t teb_out_pre = 0;
                    void *tramp_out_pre = NULL;
                    ios_lookup_thread(thread, &teb_out_pre, &tramp_out_pre);
                    void *fex_state_pre = NULL;
                    if (teb_out_pre)
                    {
                        void *cpuarea = *(void**)(teb_out_pre + 0x1788);
                        if (cpuarea) fex_state_pre = *(void**)((char*)cpuarea + 0x30);
                    }
                    uint64_t state_rip_pre = fex_state_pre ?
                        ((uint64_t*)fex_state_pre)[0x18 / 8] : 0;
                    int interesting_rip = (state_rip_pre >= 0x140079000 &&
                                           state_rip_pre <  0x14007b000) ||
                                          (state_rip_pre >= 0x1400e0000 &&
                                           state_rip_pre <  0x1400e1000);
                    if (cnt <= 3 || interesting_rip)
                    {
                        uintptr_t teb_out = teb_out_pre;
                        void *tramp_out = tramp_out_pre;
                        (void)tramp_out;
                        void *fex_state = fex_state_pre;
                        uint64_t state_rip = state_rip_pre;
                        uint64_t state_cret = fex_state ? ((uint64_t*)fex_state)[0xb0 / 8] : 0;
                        /* gs_cached is at CPUState offset 0x3e0 (after gregs,
                         * L1*, callret_sp, avx_high, xmm union, segment idxes,
                         * mxcsr, es/cs/ss/ds_cached). */
                        uint64_t state_gs = fex_state ? ((uint64_t*)fex_state)[0x3e0 / 8] : 0;
                        uint64_t teb_tls = teb_out ? *(uint64_t*)(teb_out + 0x58) : 0;
                        uint64_t gs_plus_58 = 0;
                        if (state_gs >= 0x10000 && state_gs < 0xfffffff000000000ULL)
                            gs_plus_58 = *(uint64_t*)(state_gs + 0x58);
                        dprintf(STDERR_FILENO,
                            "[x86_seg] State.gs_cached=0x%llx TEB=0x%llx TEB[0x58]=0x%llx *(gs_cached+0x58)=0x%llx\n",
                            (unsigned long long)state_gs,
                            (unsigned long long)teb_out,
                            (unsigned long long)teb_tls,
                            (unsigned long long)gs_plus_58);

                        /* LIVE x86 regs from host ARM thread state (ARM64EC SRA). */
                        uint64_t live_rax = state.__x[8];
                        uint64_t live_rcx = state.__x[0];
                        uint64_t live_rdx = state.__x[1];
                        uint64_t live_rbx = state.__x[27];
                        uint64_t live_rsp = state.__x[23];
                        uint64_t live_rbp = state.__x[29];
                        uint64_t live_rsi = state.__x[25];
                        uint64_t live_rdi = state.__x[26];
                        uint64_t live_r8  = state.__x[2];
                        uint64_t live_r9  = state.__x[3];
                        uint64_t live_r10 = state.__x[4];
                        uint64_t live_r11 = state.__x[5];
                        uint64_t live_r12 = state.__x[19];
                        uint64_t live_r13 = state.__x[20];
                        uint64_t live_r14 = state.__x[21];
                        uint64_t live_r15 = state.__x[22];
                        dprintf(STDERR_FILENO,
                            "[x86_live] RAX=0x%llx RCX=0x%llx RDX=0x%llx RBX=0x%llx RSP=0x%llx RBP=0x%llx RSI=0x%llx RDI=0x%llx\n"
                            "[x86_live]  R8=0x%llx  R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n"
                            "[x86_live] State.RIP=0x%llx callret_sp=0x%llx\n",
                            (unsigned long long)live_rax, (unsigned long long)live_rcx,
                            (unsigned long long)live_rdx, (unsigned long long)live_rbx,
                            (unsigned long long)live_rsp, (unsigned long long)live_rbp,
                            (unsigned long long)live_rsi, (unsigned long long)live_rdi,
                            (unsigned long long)live_r8,  (unsigned long long)live_r9,
                            (unsigned long long)live_r10, (unsigned long long)live_r11,
                            (unsigned long long)live_r12, (unsigned long long)live_r13,
                            (unsigned long long)live_r14, (unsigned long long)live_r15,
                            (unsigned long long)state_rip, (unsigned long long)state_cret);

                        if (live_rsp >= 0x10000 && live_rsp < 0xfffffff000000000ULL)
                        {
                            uint64_t buf[16];
                            mach_vm_size_t got = 0;
                            kern_return_t kr = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)(live_rsp - 32),
                                sizeof(buf),
                                (mach_vm_address_t)buf, &got);
                            if (kr == KERN_SUCCESS && got >= 64)
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] @RSP-32..-8: %016llx %016llx %016llx %016llx  (last = popped slot)\n",
                                    (unsigned long long)buf[0],
                                    (unsigned long long)buf[1],
                                    (unsigned long long)buf[2],
                                    (unsigned long long)buf[3]);
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] @RSP+0..+24:  %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)buf[4],
                                    (unsigned long long)buf[5],
                                    (unsigned long long)buf[6],
                                    (unsigned long long)buf[7]);
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] @RSP+32..+56: %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)buf[8],
                                    (unsigned long long)buf[9],
                                    (unsigned long long)buf[10],
                                    (unsigned long long)buf[11]);
                            }
                            else
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] vm_read RSP=0x%llx kr=%d got=%llu\n",
                                    (unsigned long long)live_rsp, kr,
                                    (unsigned long long)got);
                            }
                        }
                        else
                        {
                            dprintf(STDERR_FILENO,
                                "[x86_stk] live_rsp=0x%llx out of range — RSP not yet established\n",
                                (unsigned long long)live_rsp);
                        }

                        /* Dump [RBX..RBX+0x30] for stack-local objects: lets us
                         * see the full vector/struct state when the fault is on
                         * a `mov rax, [rcx]` chained from `mov rcx, [rbx]`. */
                        if (live_rbx >= 0x10000 && live_rbx < 0xfffffff000000000ULL)
                        {
                            uint64_t obj[7];
                            mach_vm_size_t got2 = 0;
                            kern_return_t kr2 = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)live_rbx,
                                sizeof(obj),
                                (mach_vm_address_t)obj, &got2);
                            if (kr2 == KERN_SUCCESS && got2 >= sizeof(obj))
                                dprintf(STDERR_FILENO,
                                    "[x86_obj] @RBX+0..+0x30: %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)obj[0],
                                    (unsigned long long)obj[1],
                                    (unsigned long long)obj[2],
                                    (unsigned long long)obj[3],
                                    (unsigned long long)obj[4],
                                    (unsigned long long)obj[5],
                                    (unsigned long long)obj[6]);
                        }

                        /* Also dump [RCX..RCX+0x30] — when the fault is in a
                         * helper that took (rcx=this, ...) and `this` got
                         * clobbered by intermediate moves, the original `this`
                         * lives in RBX. But RCX itself often points to a
                         * destination buffer or an object whose state we want
                         * to inspect. */
                        if (live_rcx >= 0x10000 && live_rcx < 0xfffffff000000000ULL)
                        {
                            uint64_t obj[7];
                            mach_vm_size_t got_c = 0;
                            kern_return_t kr_c = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)live_rcx,
                                sizeof(obj),
                                (mach_vm_address_t)obj, &got_c);
                            if (kr_c == KERN_SUCCESS && got_c >= sizeof(obj))
                                dprintf(STDERR_FILENO,
                                    "[x86_dst] @RCX+0..+0x30: %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)obj[0],
                                    (unsigned long long)obj[1],
                                    (unsigned long long)obj[2],
                                    (unsigned long long)obj[3],
                                    (unsigned long long)obj[4],
                                    (unsigned long long)obj[5],
                                    (unsigned long long)obj[6]);
                        }

                        /* Thumper-debug: also dump the static singleton slot
                         * at 0x140290a60+0x428. This is the "0x1400793d0
                         * caller" that the DXGI dispatch wrapper reads from.
                         * If it's the static placeholder 0x1401825a8, Thumper
                         * never initialized the real renderer wrapper at this
                         * slot. If it's something else, we need to see what. */
                        {
                            uint64_t static_slot = 0;
                            mach_vm_size_t got_ss = 0;
                            if (mach_vm_read_overwrite(mach_task_self(),
                                    (mach_vm_address_t)0x140290e88ULL, /* 0x140290a60+0x428 */
                                    sizeof(static_slot),
                                    (mach_vm_address_t)&static_slot, &got_ss)
                                == KERN_SUCCESS && got_ss == sizeof(static_slot))
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_thumper] [0x140290a60+0x428]=0x%llx",
                                    (unsigned long long)static_slot);
                                /* Walk the chain: renderer object → vtable → vtable[30] */
                                if (static_slot >= 0x10000 && static_slot < 0xfffffff000000000ULL)
                                {
                                    uint64_t vtable_ptr = 0;
                                    mach_vm_size_t got_v = 0;
                                    if (mach_vm_read_overwrite(mach_task_self(),
                                            (mach_vm_address_t)static_slot,
                                            sizeof(vtable_ptr),
                                            (mach_vm_address_t)&vtable_ptr, &got_v)
                                        == KERN_SUCCESS && got_v == sizeof(vtable_ptr))
                                    {
                                        dprintf(STDERR_FILENO, "  vtable=*[slot]=0x%llx",
                                            (unsigned long long)vtable_ptr);
                                        if (vtable_ptr >= 0x10000 && vtable_ptr < 0xfffffff000000000ULL)
                                        {
                                            /* Read full vtable slots [0..7] and [30] */
                                            uint64_t vt_entries[32];
                                            mach_vm_size_t got_ve = 0;
                                            if (mach_vm_read_overwrite(mach_task_self(),
                                                    (mach_vm_address_t)vtable_ptr,
                                                    sizeof(vt_entries),
                                                    (mach_vm_address_t)vt_entries, &got_ve)
                                                == KERN_SUCCESS && got_ve == sizeof(vt_entries))
                                            {
                                                dprintf(STDERR_FILENO,
                                                    "\n[x86_thumper]   vtable[0..3]: %016llx %016llx %016llx %016llx",
                                                    (unsigned long long)vt_entries[0],
                                                    (unsigned long long)vt_entries[1],
                                                    (unsigned long long)vt_entries[2],
                                                    (unsigned long long)vt_entries[3]);
                                                dprintf(STDERR_FILENO,
                                                    "\n[x86_thumper]   vtable[28..31] (target=[30]): %016llx %016llx ★%016llx %016llx",
                                                    (unsigned long long)vt_entries[28],
                                                    (unsigned long long)vt_entries[29],
                                                    (unsigned long long)vt_entries[30],
                                                    (unsigned long long)vt_entries[31]);
                                            }
                                        }
                                    }
                                }
                                dprintf(STDERR_FILENO, "\n");
                            }
                        }

                        /* Thumper-debug: when fault chain involves the renderer
                         * wrapper at guest RIP 0x140079390 (vtable[30] dispatch),
                         * dump the indirection chain [rcx+0x428] → [rax] → [r10+0xf0].
                         * Helps identify when [rcx+0x428] is the wrong type
                         * (vtable instead of object, etc.) per GPT diagnosis. */
                        if (live_rcx >= 0x10000 && live_rcx < 0xfffffff000000000ULL)
                        {
                            mach_vm_address_t f1_addr = (mach_vm_address_t)(live_rcx + 0x428);
                            uint64_t f1 = 0;
                            mach_vm_size_t got_f1 = 0;
                            if (mach_vm_read_overwrite(mach_task_self(), f1_addr,
                                    sizeof(f1), (mach_vm_address_t)&f1, &got_f1)
                                == KERN_SUCCESS && got_f1 == sizeof(f1))
                            {
                                dprintf(STDERR_FILENO, "[x86_dispatch] [RCX+0x428]=0x%llx",
                                    (unsigned long long)f1);
                                if (f1 >= 0x10000 && f1 < 0xfffffff000000000ULL)
                                {
                                    uint64_t f2 = 0;
                                    mach_vm_size_t got_f2 = 0;
                                    if (mach_vm_read_overwrite(mach_task_self(),
                                            (mach_vm_address_t)f1, sizeof(f2),
                                            (mach_vm_address_t)&f2, &got_f2)
                                        == KERN_SUCCESS && got_f2 == sizeof(f2))
                                    {
                                        dprintf(STDERR_FILENO, " [[+0x428]]=0x%llx",
                                            (unsigned long long)f2);
                                        if (f2 >= 0x10000 && f2 < 0xfffffff000000000ULL)
                                        {
                                            uint64_t slot30 = 0;
                                            mach_vm_size_t got_s = 0;
                                            if (mach_vm_read_overwrite(mach_task_self(),
                                                    (mach_vm_address_t)(f2 + 0xf0),
                                                    sizeof(slot30),
                                                    (mach_vm_address_t)&slot30, &got_s)
                                                == KERN_SUCCESS && got_s == sizeof(slot30))
                                            {
                                                dprintf(STDERR_FILENO,
                                                    " [+0xf0]=0x%llx (would-be vtable[30])",
                                                    (unsigned long long)slot30);
                                            }
                                        }
                                    }
                                }
                                dprintf(STDERR_FILENO, "\n");
                            }
                        }

                        /* Walk FEX's callret stack to recover the guest call chain.
                         * Each entry is 16 bytes: [0..7]=guest return RIP, [8..15]=host
                         * return PC. callret_sp points at the most-recently-pushed
                         * entry; entries grow DOWN (push pre-decrements by 0x10). */
                        if (state_cret >= 0x10000 && state_cret < 0xfffffff000000000ULL)
                        {
                            uint64_t cr[16]; /* up to 8 entries */
                            mach_vm_size_t got3 = 0;
                            kern_return_t kr3 = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)state_cret,
                                sizeof(cr),
                                (mach_vm_address_t)cr, &got3);
                            if (kr3 == KERN_SUCCESS && got3 >= sizeof(cr))
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_callret] guest call chain (most recent first):\n"
                                    "  [0] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [1] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [2] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [3] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [4] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [5] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [6] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [7] retRIP=0x%llx hostPC=0x%llx\n",
                                    (unsigned long long)cr[0],  (unsigned long long)cr[1],
                                    (unsigned long long)cr[2],  (unsigned long long)cr[3],
                                    (unsigned long long)cr[4],  (unsigned long long)cr[5],
                                    (unsigned long long)cr[6],  (unsigned long long)cr[7],
                                    (unsigned long long)cr[8],  (unsigned long long)cr[9],
                                    (unsigned long long)cr[10], (unsigned long long)cr[11],
                                    (unsigned long long)cr[12], (unsigned long long)cr[13],
                                    (unsigned long long)cr[14], (unsigned long long)cr[15]);
                            }
                        }
                    }
                }
            }
        }

        /* Build reply */
        ios_exc_reply_t reply;
        reply.head.msgh_bits = MACH_MSGH_BITS( MACH_MSGH_BITS_REMOTE(req->head.msgh_bits), 0 );
        reply.head.msgh_size = sizeof(reply);
        reply.head.msgh_remote_port = req->head.msgh_remote_port;
        reply.head.msgh_local_port = MACH_PORT_NULL;
        reply.head.msgh_id = req->head.msgh_id + 100;
        reply.ndr = NDR_record;
        reply.ret_code = handled ? KERN_SUCCESS : KERN_FAILURE;

        mach_msg( &reply.head, MACH_SEND_MSG, sizeof(reply), 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL );

        /* Deallocate the send rights we received */
        mach_port_deallocate( mach_task_self(), thread );
        mach_port_deallocate( mach_task_self(), req->task.name );
    }
    return NULL;
}

/* Register a Wine "process" thread with the shared Mach exception handler.
 * First call creates the shared port and handler thread.
 * Every call registers the thread and sets its exception ports. */
static void ios_setup_mach_exception_handler( thread_t pe_thread, uintptr_t teb,
                                               void *trampoline )
{
    /* One-time initialization: create shared port and handler thread */
    if (!ios_exc_handler_started)
    {
        extern struct _KUSER_SHARED_DATA *user_shared_data;
        ios_exc_usd = (uintptr_t)user_shared_data;

        kern_return_t kr = mach_port_allocate( mach_task_self(),
                                                MACH_PORT_RIGHT_RECEIVE, &ios_exc_port );
        if (kr != KERN_SUCCESS) { ERR("mach exc port allocate: kr=%d\n", kr); return; }

        kr = mach_port_insert_right( mach_task_self(), ios_exc_port, ios_exc_port,
                                      MACH_MSG_TYPE_MAKE_SEND );
        if (kr != KERN_SUCCESS) { ERR("mach exc port insert: kr=%d\n", kr); return; }

        pthread_t handler;
        pthread_create( &handler, NULL, ios_mach_exception_thread,
                        (void *)(uintptr_t)ios_exc_port );
        pthread_detach( handler );

        /* Stale-pointer heal scanner (see ios_stale_va_scanner above). */
        {
            pthread_t healer;
            pthread_create( &healer, NULL, ios_stale_va_scanner, NULL );
            pthread_detach( healer );
        }

        ios_exc_handler_started = 1;
    }

    /* Register this thread in the registry */
    int idx = __sync_fetch_and_add(&ios_thread_count, 1);
    if (idx < IOS_MAX_WINE_THREADS)
    {
        ios_thread_registry[idx].mach_thread = pe_thread;
        ios_thread_registry[idx].teb = teb;
        ios_thread_registry[idx].trampoline = trampoline;
    }

    /* Set exception port for this thread (shared port) */
    kern_return_t kr = thread_set_exception_ports( pe_thread,
                                      EXC_MASK_BAD_ACCESS,
                                      ios_exc_port,
                                      (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
                                      ARM_THREAD_STATE64 );
    if (kr != KERN_SUCCESS) { ERR("mach exc set ports: kr=%d thread=0x%x\n", kr, pe_thread); return; }

    ERR("Mach exception handler registered thread 0x%x (idx=%d), teb=%p tramp=%p usd=%p\n",
        pe_thread, idx, (void*)teb, trampoline, (void*)ios_exc_usd);
}
#endif


/***********************************************************************
 *           context_init_empty_xstate
 *
 * Initializes a context's CONTEXT_EX structure to point to an empty xstate buffer
 */
static inline void context_init_empty_xstate( CONTEXT *context, void *xstate_buffer )
{
    CONTEXT_EX *xctx;

    xctx = (CONTEXT_EX *)(context + 1);
    xctx->Legacy.Length = sizeof(CONTEXT);
    xctx->Legacy.Offset = -(LONG)sizeof(CONTEXT);
    xctx->XState.Length = 0;
    xctx->XState.Offset = (BYTE *)xstate_buffer - (BYTE *)xctx;
    xctx->All.Length = sizeof(CONTEXT) + xctx->XState.Offset + xctx->XState.Length;
    xctx->All.Offset = -(LONG)sizeof(CONTEXT);
}

void set_process_instrumentation_callback( void *callback )
{
    if (callback) FIXME( "Not supported.\n" );
}


/***********************************************************************
 *           syscall_frame_fixup_for_fastpath
 *
 * Fixes up the given syscall frame such that the syscall dispatcher
 * can return via the fast path if CONTEXT_INTEGER is set in
 * restore_flags.
 *
 * Clobbers the frame's X16 and X17 register values.
 */
static void syscall_frame_fixup_for_fastpath( struct syscall_frame *frame )
{
    frame->x[16] = frame->pc;
    frame->x[17] = frame->sp;
}

/***********************************************************************
 *           save_fpu
 *
 * Set the FPU context from a sigcontext.
 */
static void save_fpu( CONTEXT *context, const ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = fp->fpcr;
    context->Fpsr = fp->fpsr;
    memcpy( context->V, fp->vregs, sizeof(context->V) );
#elif defined(__APPLE__)
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = sigcontext->uc_mcontext->__ns.__fpcr;
    context->Fpsr = sigcontext->uc_mcontext->__ns.__fpsr;
    memcpy( context->V, sigcontext->uc_mcontext->__ns.__v, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           restore_fpu
 *
 * Restore the FPU context to a sigcontext.
 */
static void restore_fpu( const CONTEXT *context, ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    fp->fpcr = context->Fpcr;
    fp->fpsr = context->Fpsr;
    memcpy( fp->vregs, context->V, sizeof(fp->vregs) );
#elif defined(__APPLE__)
    sigcontext->uc_mcontext->__ns.__fpcr = context->Fpcr;
    sigcontext->uc_mcontext->__ns.__fpsr = context->Fpsr;
    memcpy( sigcontext->uc_mcontext->__ns.__v, context->V, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           save_context
 *
 * Set the register values from a sigcontext.
 */
static void save_context( CONTEXT *context, const ucontext_t *sigcontext )
{
    DWORD i;

    context->ContextFlags = CONTEXT_FULL;
    context->Fp   = FP_sig(sigcontext);     /* Frame pointer */
    context->Lr   = LR_sig(sigcontext);     /* Link register */
    context->Sp   = SP_sig(sigcontext);     /* Stack pointer */
    context->Pc   = PC_sig(sigcontext);     /* Program Counter */
    context->Cpsr = PSTATE_sig(sigcontext); /* Current State Register */
    for (i = 0; i <= 28; i++) context->X[i] = REGn_sig( i, sigcontext );
    save_fpu( context, sigcontext );
}


/***********************************************************************
 *           restore_context
 *
 * Build a sigcontext from the register values.
 */
static void restore_context( const CONTEXT *context, ucontext_t *sigcontext )
{
    DWORD i;

    FP_sig(sigcontext)     = context->Fp;   /* Frame pointer */
    LR_sig(sigcontext)     = context->Lr;   /* Link register */
    SP_sig(sigcontext)     = context->Sp;   /* Stack pointer */
    PC_sig(sigcontext)     = context->Pc;   /* Program Counter */
    PSTATE_sig(sigcontext) = context->Cpsr; /* Current State Register */
    for (i = 0; i <= 28; i++) REGn_sig( i, sigcontext ) = context->X[i];
    restore_fpu( context, sigcontext );
}


/***********************************************************************
 *           signal_set_full_context
 */
NTSTATUS signal_set_full_context( CONTEXT *context )
{
    extern int ios_is_arm64ec_cur(void);
    struct syscall_frame *frame = get_syscall_frame();
    NTSTATUS status = NtSetContextThread( GetCurrentThread(), context );

    if (!status && (context->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
        frame->restore_flags |= CONTEXT_INTEGER;

    /* iOS-Mythic diag (Thumper desktop ILL): the crash pc is entered with no
     * branch/register/immediate trail = a context restore. Log every resume
     * targeting the FEX tail-carve region (top 128MB of the pool) whose
     * first word is a data-word/NOP — plus the is_ec_code verdict, since
     * non-EC resumes get bounced through KiUserEmulationDispatcher. */
    {
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        size_t psz = ios_jit_pool_size_global;
        if (rx && psz && frame->pc >= rx + psz / 2 && frame->pc < rx + psz)
        {
            uint32_t w = *(uint32_t *)frame->pc;
            if ((w >> 16) == 0 || w == 0xd503201fu)
                dprintf(2, "[set-ctx] SUSPICIOUS resume: pc=%p first_insn=0x%08x is_ec=%d lr=%p sp=%p (Pc from context=%p)\n",
                        (void *)frame->pc, w, is_ec_code( frame->pc ),
                        (void *)frame->lr, (void *)frame->sp, (void *)context->Pc);
        }
    }

    if (ios_is_arm64ec_cur() && !is_ec_code( frame->pc ))   /* owner-aware (X3) */
    {
        CONTEXT *user_context = (CONTEXT *)((frame->sp - sizeof(CONTEXT)) & ~15);

        user_context->ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), user_context );
        frame->sp = (ULONG_PTR)user_context;
        frame->pc = (ULONG_PTR)IOS_PFUNC(KiUserEmulationDispatcher);
    }
    return status;
}


/***********************************************************************
 *              get_native_context
 */
void *get_native_context( CONTEXT *context )
{
    return context;
}


/***********************************************************************
 *              get_wow_context
 */
void *get_wow_context( CONTEXT *context )
{
    /* Owner-aware (X3): the CPU area machine follows the current thread's
     * pseudo-process, not the session's main exe. */
    extern const SECTION_IMAGE_INFORMATION *ios_cur_image_info(void);
    return get_cpu_area( ios_cur_image_info()->Machine );
}


/***********************************************************************
 *              NtSetContextThread  (NTDLL.@)
 *              ZwSetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    NTSTATUS ret = STATUS_SUCCESS;
    BOOL self = (handle == GetCurrentThread());
    DWORD flags = context->ContextFlags & ~CONTEXT_ARM64;

    if (self && (flags & CONTEXT_DEBUG_REGISTERS)) self = FALSE;

    /* iOS-Mythic diag: companion to [set-ctx] in signal_set_full_context —
     * catch cross-thread PC rewrites into the FEX tail carve that land on
     * data words (suspend/invalidate machinery redirecting threads). */
    if (flags & CONTEXT_CONTROL)
    {
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        size_t psz = ios_jit_pool_size_global;
        if (rx && psz && context->Pc >= rx + psz / 2 && context->Pc < rx + psz)
        {
            uint32_t w = *(uint32_t *)context->Pc;
            if ((w >> 16) == 0 || w == 0xd503201fu)
                dprintf(2, "[set-ctx] SUSPICIOUS NtSetContextThread: self=%d pc=%p first_insn=0x%08x lr=%p\n",
                        self, (void *)context->Pc, w, (void *)context->Lr);
        }
    }

    if (!self)
    {
        ret = set_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (flags & CONTEXT_INTEGER)
    {
        memcpy( frame->x, context->X, sizeof(context->X[0]) * 18 );
        /* skip x18 */
        memcpy( frame->x + 19, context->X + 19, sizeof(context->X[0]) * 10 );
    }
    if (flags & CONTEXT_CONTROL)
    {
        frame->fp    = context->Fp;
        frame->lr    = context->Lr;
        frame->sp    = context->Sp;
        frame->pc    = context->Pc;
        frame->cpsr  = context->Cpsr;
    }
    if (flags & CONTEXT_FLOATING_POINT)
    {
        frame->fpcr = context->Fpcr;
        frame->fpsr = context->Fpsr;
        memcpy( frame->v, context->V, sizeof(frame->v) );
    }
    if (flags & CONTEXT_ARM64_X18)
    {
        frame->x[18] = context->X[18];
    }
    if (flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    frame->restore_flags |= flags & ~CONTEXT_INTEGER;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtGetContextThread  (NTDLL.@)
 *              ZwGetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM64;
    BOOL self = (handle == GetCurrentThread());

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (needed_flags & CONTEXT_INTEGER)
    {
        memcpy( context->X, frame->x, sizeof(context->X[0]) * 29 );
        context->ContextFlags |= CONTEXT_INTEGER;
    }
    if (needed_flags & CONTEXT_CONTROL)
    {
        context->Fp   = frame->fp;
        context->Lr   = frame->lr;
        context->Sp   = frame->sp;
        context->Pc   = frame->pc;
        context->Cpsr = frame->cpsr;
        context->ContextFlags |= CONTEXT_CONTROL;
    }
    if (needed_flags & CONTEXT_FLOATING_POINT)
    {
        context->Fpcr = frame->fpcr;
        context->Fpsr = frame->fpsr;
        memcpy( context->V, frame->v, sizeof(context->V) );
        context->ContextFlags |= CONTEXT_FLOATING_POINT;
    }
    if (needed_flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              set_thread_wow64_context
 */
NTSTATUS set_thread_wow64_context( HANDLE handle, const void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = set_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame;
        const I386_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_i386;

        if (flags & CONTEXT_I386_INTEGER)
        {
            wow_frame->Eax = context->Eax;
            wow_frame->Ebx = context->Ebx;
            wow_frame->Ecx = context->Ecx;
            wow_frame->Edx = context->Edx;
            wow_frame->Esi = context->Esi;
            wow_frame->Edi = context->Edi;
        }
        if (flags & CONTEXT_I386_CONTROL)
        {
            WOW64_CPURESERVED *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];

            wow_frame->Esp    = context->Esp;
            wow_frame->Ebp    = context->Ebp;
            wow_frame->Eip    = context->Eip;
            wow_frame->EFlags = context->EFlags;
            wow_frame->SegCs  = context->SegCs;
            wow_frame->SegSs  = context->SegSs;
            cpu->Flags |= WOW64_CPURESERVED_FLAG_RESET_STATE;
        }
        if (flags & CONTEXT_I386_SEGMENTS)
        {
            wow_frame->SegDs = context->SegDs;
            wow_frame->SegEs = context->SegEs;
            wow_frame->SegFs = context->SegFs;
            wow_frame->SegGs = context->SegGs;
        }
        if (flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            wow_frame->Dr0 = context->Dr0;
            wow_frame->Dr1 = context->Dr1;
            wow_frame->Dr2 = context->Dr2;
            wow_frame->Dr3 = context->Dr3;
            wow_frame->Dr6 = context->Dr6;
            wow_frame->Dr7 = context->Dr7;
        }
        if (flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( &wow_frame->ExtendedRegisters, context->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
        }
        if (flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &wow_frame->FloatSave, &context->FloatSave, sizeof(context->FloatSave) );
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame;
        const ARM_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_ARM;

        if (flags & CONTEXT_INTEGER)
        {
            wow_frame->R0  = context->R0;
            wow_frame->R1  = context->R1;
            wow_frame->R2  = context->R2;
            wow_frame->R3  = context->R3;
            wow_frame->R4  = context->R4;
            wow_frame->R5  = context->R5;
            wow_frame->R6  = context->R6;
            wow_frame->R7  = context->R7;
            wow_frame->R8  = context->R8;
            wow_frame->R9  = context->R9;
            wow_frame->R10 = context->R10;
            wow_frame->R11 = context->R11;
            wow_frame->R12 = context->R12;
        }
        if (flags & CONTEXT_CONTROL)
        {
            wow_frame->Sp = context->Sp;
            wow_frame->Lr = context->Lr;
            wow_frame->Pc = context->Pc & ~1;
            wow_frame->Cpsr = context->Cpsr;
            if (context->Cpsr & 0x20) wow_frame->Pc |= 1; /* thumb */
        }
        if (flags & CONTEXT_FLOATING_POINT)
        {
            wow_frame->Fpscr = context->Fpscr;
            memcpy( wow_frame->D, context->D, sizeof(context->D) );
        }
        break;
    }

    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              get_thread_wow64_context
 */
NTSTATUS get_thread_wow64_context( HANDLE handle, void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_i386;

        if (needed_flags & CONTEXT_I386_INTEGER)
        {
            context->Eax = wow_frame->Eax;
            context->Ebx = wow_frame->Ebx;
            context->Ecx = wow_frame->Ecx;
            context->Edx = wow_frame->Edx;
            context->Esi = wow_frame->Esi;
            context->Edi = wow_frame->Edi;
            context->ContextFlags |= CONTEXT_I386_INTEGER;
        }
        if (needed_flags & CONTEXT_I386_CONTROL)
        {
            context->Esp    = wow_frame->Esp;
            context->Ebp    = wow_frame->Ebp;
            context->Eip    = wow_frame->Eip;
            context->EFlags = wow_frame->EFlags;
            context->SegCs  = wow_frame->SegCs;
            context->SegSs  = wow_frame->SegSs;
            context->ContextFlags |= CONTEXT_I386_CONTROL;
        }
        if (needed_flags & CONTEXT_I386_SEGMENTS)
        {
            context->SegDs = wow_frame->SegDs;
            context->SegEs = wow_frame->SegEs;
            context->SegFs = wow_frame->SegFs;
            context->SegGs = wow_frame->SegGs;
            context->ContextFlags |= CONTEXT_I386_SEGMENTS;
        }
        if (needed_flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( context->ExtendedRegisters, &wow_frame->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
            context->ContextFlags |= CONTEXT_I386_EXTENDED_REGISTERS;
        }
        if (needed_flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &context->FloatSave, &wow_frame->FloatSave, sizeof(context->FloatSave) );
            context->ContextFlags |= CONTEXT_I386_FLOATING_POINT;
        }
        if (needed_flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            context->Dr0 = wow_frame->Dr0;
            context->Dr1 = wow_frame->Dr1;
            context->Dr2 = wow_frame->Dr2;
            context->Dr3 = wow_frame->Dr3;
            context->Dr6 = wow_frame->Dr6;
            context->Dr7 = wow_frame->Dr7;
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM;

        if (needed_flags & CONTEXT_INTEGER)
        {
            context->R0  = wow_frame->R0;
            context->R1  = wow_frame->R1;
            context->R2  = wow_frame->R2;
            context->R3  = wow_frame->R3;
            context->R4  = wow_frame->R4;
            context->R5  = wow_frame->R5;
            context->R6  = wow_frame->R6;
            context->R7  = wow_frame->R7;
            context->R8  = wow_frame->R8;
            context->R9  = wow_frame->R9;
            context->R10 = wow_frame->R10;
            context->R11 = wow_frame->R11;
            context->R12 = wow_frame->R12;
            context->ContextFlags |= CONTEXT_INTEGER;
        }
        if (needed_flags & CONTEXT_CONTROL)
        {
            context->Sp   = wow_frame->Sp;
            context->Lr   = wow_frame->Lr;
            context->Pc   = wow_frame->Pc;
            context->Cpsr = wow_frame->Cpsr;
            context->ContextFlags |= CONTEXT_CONTROL;
        }
        if (needed_flags & CONTEXT_FLOATING_POINT)
        {
            context->Fpscr = wow_frame->Fpscr;
            memcpy( context->D, wow_frame->D, sizeof(wow_frame->D) );
            context->ContextFlags |= CONTEXT_FLOATING_POINT;
        }
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    }
    return STATUS_SUCCESS;
}


#ifdef WINE_IOS
static inline void ios_fixup_x18_for_return( ucontext_t *context );
#endif

/***********************************************************************
 *           setup_raise_exception
 */
/* task #24 probe: Thumper's settings page dies via its own ExitProcess(-1)
 * with the actual failure invisible (handled guest exception / C++ throw /
 * OutputDebugString we never see). Log every exception dispatched to the
 * guest: code+address+params. DBG_PRINTEXCEPTION carries the game's own
 * debug string — print it. 0xE06D7363 = MSVC C++ throw. */
static void ios_log_guest_exception( const char *via, const EXCEPTION_RECORD *rec, ULONG64 pc )
{
    static volatile int exc_logged = 0;
    int n = __sync_add_and_fetch(&exc_logged, 1);
    if (n > 80) return;
    dprintf(2, "[exc-disp] %s tid=%04x code=%08x flags=%x addr=%p pc=%llx nparams=%u p0=%llx p1=%llx\n",
            via, (unsigned int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
            (unsigned int)rec->ExceptionCode, (unsigned int)rec->ExceptionFlags,
            rec->ExceptionAddress, (unsigned long long)pc, (unsigned int)rec->NumberParameters,
            rec->NumberParameters > 0 ? (unsigned long long)rec->ExceptionInformation[0] : 0,
            rec->NumberParameters > 1 ? (unsigned long long)rec->ExceptionInformation[1] : 0);
    if (rec->ExceptionCode == 0x40010006 && rec->NumberParameters >= 2 &&
        rec->ExceptionInformation[1])   /* DBG_PRINTEXCEPTION_C: [0]=len [1]=char* */
        dprintf(2, "[exc-disp]   OutputDebugStringA: \"%.*s\"\n",
                (int)(rec->ExceptionInformation[0] > 512 ? 512 : rec->ExceptionInformation[0]),
                (const char *)rec->ExceptionInformation[1]);
    if (rec->ExceptionCode == 0x4001000a && rec->NumberParameters >= 2 &&
        rec->ExceptionInformation[1])   /* DBG_PRINTEXCEPTION_WIDE_C */
    {
        const WCHAR *ws = (const WCHAR *)rec->ExceptionInformation[1];
        char buf[256];
        int i;
        for (i = 0; i < 255 && ws[i]; i++) buf[i] = (ws[i] < 128) ? (char)ws[i] : '?';
        buf[i] = 0;
        dprintf(2, "[exc-disp]   OutputDebugStringW: \"%s\"\n", buf);
    }
}

static void setup_raise_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct exc_stack_layout *stack;
    void *stack_ptr = (void *)(SP_sig(sigcontext) & ~15);
    NTSTATUS status;

    ios_log_guest_exception( "raise", rec, context->Pc );

    status = send_debug_event( rec, context, TRUE, TRUE );
    if (status == DBG_CONTINUE || status == DBG_EXCEPTION_HANDLED)
    {
        restore_context( context, sigcontext );
#ifdef WINE_IOS
        ios_fixup_x18_for_return( sigcontext );
#endif
        return;
    }

    /* fix up instruction pointer in context for EXCEPTION_BREAKPOINT */
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) context->Pc -= 4;

    stack = virtual_setup_exception( stack_ptr, sizeof(*stack), rec );
    stack->rec = *rec;
    stack->context = *context;
    context_init_empty_xstate( &stack->context, stack->redzone );

    SP_sig(sigcontext) = (ULONG_PTR)stack;
    PC_sig(sigcontext) = (ULONG_PTR)IOS_PFUNC(KiUserExceptionDispatcher);
    REGn_sig(18, sigcontext) = (ULONG_PTR)NtCurrentTeb();
#ifdef WINE_IOS
    /* iOS sigreturn zeroes x18 — route through trampoline */
    ios_fixup_x18_for_return( sigcontext );
#endif
}


/***********************************************************************
 *           setup_exception
 *
 * Modify the signal context to call the exception raise function.
 */
static void setup_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec )
{
    CONTEXT context;

    rec->ExceptionAddress = (void *)PC_sig(sigcontext);
#ifdef WINE_IOS
    /* task#34 guest-exception-DISPATCH: when the faulting pc is inside a
     * JIT-pool IMAGE COPY, the guest-visible record must carry the PE VA —
     * handlers compare ExceptionAddress against module bounds and the SEH
     * machinery resolves unwind info by module. (pcs inside FEX-emitted
     * code translate to nothing here and are left alone — reconstructing
     * the guest RIP for those is ResetToConsistentState's job on the PE
     * side.) The resume context keeps the real host pc. */
    {
        extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
        uint64_t pe = ios_jit_reverse_translate( (uint64_t)PC_sig(sigcontext), NULL );
        if (pe)
        {
            rec->ExceptionAddress = (void *)(uintptr_t)pe;
            { static unsigned long pe_storm; if (ios_sig_storm_gate( &pe_storm ))
            ERR( "setup_exception: pool pc %p -> PE ExceptionAddress %p\n",
                 (void *)PC_sig(sigcontext), rec->ExceptionAddress ); }
        }
    }
#endif
    save_context( &context, sigcontext );
    setup_raise_exception( sigcontext, rec, &context );
}


/***********************************************************************
 *           call_user_apc_dispatcher
 */
NTSTATUS call_user_apc_dispatcher( CONTEXT *context, unsigned int flags, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                   PNTAPCFUNC func, NTSTATUS status )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = context ? context->Sp : frame->sp;
    struct apc_stack_layout *stack;

    if (flags) FIXME( "flags %#x are not supported.\n", flags );

    sp &= ~15;
    stack = (struct apc_stack_layout *)sp - 1;
    if (context)
    {
        memmove( &stack->context, context, sizeof(stack->context) );
        NtSetContextThread( GetCurrentThread(), &stack->context );
    }
    else
    {
        stack->context.ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), &stack->context );
        stack->context.X0 = status;
    }
    stack->func      = func;
    stack->args[0]   = arg1;
    stack->args[1]   = arg2;
    stack->args[2]   = arg3;
    stack->alertable = TRUE;

    frame->sp = (ULONG64)stack;
    frame->pc = (ULONG64)IOS_PFUNC(KiUserApcDispatcher);
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_raise_user_exception_dispatcher
 */
void call_raise_user_exception_dispatcher(void)
{
    get_syscall_frame()->pc = (UINT64)pKiRaiseUserExceptionDispatcher;
}


/***********************************************************************
 *           call_user_exception_dispatcher
 */
NTSTATUS call_user_exception_dispatcher( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    struct exc_stack_layout *stack;
    NTSTATUS status;

    ios_log_guest_exception( "dispatch", rec, context->Pc );

    status = NtSetContextThread( GetCurrentThread(), context );

    if (status) return status;
    stack = (struct exc_stack_layout *)(context->Sp & ~15) - 1;
    memmove( &stack->context, context, sizeof(*context) );
    memmove( &stack->rec, rec, sizeof(*rec) );
    context_init_empty_xstate( &stack->context, stack->redzone );

    frame->pc = (ULONG64)IOS_PFUNC(KiUserExceptionDispatcher);
    frame->sp = (ULONG64)stack;
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_user_mode_callback
 */
extern NTSTATUS call_user_mode_callback( ULONG64 user_sp, void **ret_ptr, ULONG *ret_len,
                                         void *func, TEB *teb );
__ASM_GLOBAL_FUNC( call_user_mode_callback,
                   "stp x29, x30, [sp,#-0xd0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xd0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xd0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xc8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "stp x1, x2, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "mov x18, x4\n\t"              /* teb */
                   "mrs x1, fpcr\n\t"
                   "mrs x2, fpsr\n\t"
                   "bfi x1, x2, #0, #32\n\t"
                   "ldr x2, [x18]\n\t"            /* teb->Tib.ExceptionList */
                   "stp x1, x2, [x29, #0xb0]\n\t"

                   "ldr x7, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "sub x1, sp, #0x330\n\t"       /* sizeof(struct syscall_frame) */
                   "str x1, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x1, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "ldr w11, [x18, #0x380]\n\t"   /* thread_data->syscall_trace */
                   "cbnz x11, 1f\n\t"
                   /* switch to user stack */
                   "mov sp, x0\n\t"               /* user_sp */
                   "br x3\n"
                   "1:\tmov x19, x18\n\t"         /* teb */
                   "mov x20, x0\n\t"              /* user_sp */
                   "mov x21, x3\n\t"              /* func */
                   "mov sp, x1\n\t"
                   "ldr x1, [x20]\n\t"            /* args */
                   "ldp w2, w0, [x20, #8]\n\t"    /* len, id */
                   "str x0, [x29, #0xc0]\n\t"     /* id */
                   "bl " __ASM_NAME("trace_usercall") "\n\t"
                   "mov x18, x19\n\t"             /* teb */
                   "mov sp, x20\n\t"              /* user_sp */
                   "br x21" )


/***********************************************************************
 *           user_mode_callback_return
 */
extern void DECLSPEC_NORETURN user_mode_callback_return( void *ret_ptr, ULONG ret_len,
                                                         NTSTATUS status, TEB *teb );
__ASM_GLOBAL_FUNC( user_mode_callback_return,
                   "ldr x4, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "ldp x5, x29, [x4,#0x110]\n\t" /* prev_frame,syscall_cfa */
                   "str x5, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "sub x29, x29, #0xd0\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   __ASM_CFI(".cfi_rel_offset 29,0x00\n\t")
                   __ASM_CFI(".cfi_rel_offset 30,0x08\n\t")
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "ldp x5, x6, [x29, #0xb0]\n\t"
                   "str x6, [x3]\n\t"             /* teb->Tib.ExceptionList */
                   "msr fpcr, x5\n\t"
                   "lsr x5, x5, #32\n\t"
                   "msr fpsr, x5\n\t"
                   "ldp x5, x6, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "str x0, [x5]\n\t"             /* ret_ptr */
                   "str w1, [x6]\n\t"             /* ret_len */
                   "ldr w11, [x3, #0x380]\n\t"    /* thread_data->syscall_trace */
                   "cbz x11, 1f\n\t"
                   "ldr w3, [x29, #0xc0]\n\t"     /* id */
                   "mov x19, x2\n\t"
                   "bl " __ASM_NAME("trace_userret") "\n\t"
                   "mov x2, x19\n"                /* status */
                   "1:\tldp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_same_value 19\n\t")
                   __ASM_CFI(".cfi_same_value 20\n\t")
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_same_value 21\n\t")
                   __ASM_CFI(".cfi_same_value 22\n\t")
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_same_value 23\n\t")
                   __ASM_CFI(".cfi_same_value 24\n\t")
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_same_value 25\n\t")
                   __ASM_CFI(".cfi_same_value 26\n\t")
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_same_value 27\n\t")
                   __ASM_CFI(".cfi_same_value 28\n\t")
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "mov x0, x2\n\t"               /* status */
                   "mov sp, x29\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )


/***********************************************************************
 *           user_mode_abort_thread
 */
extern void DECLSPEC_NORETURN user_mode_abort_thread( NTSTATUS status, struct syscall_frame *frame );
__ASM_GLOBAL_FUNC( user_mode_abort_thread,
                   "ldr x1, [x1, #0x118]\n\t"    /* frame->syscall_cfa */
                   "sub x29, x1, #0xc0\n\t"
                   /* switch to kernel stack */
                   "mov sp, x29\n\t"
                   __ASM_CFI(".cfi_def_cfa 29,0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19,-0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20,-0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21,-0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22,-0x98\n\t")
                   __ASM_CFI(".cfi_offset 23,-0x90\n\t")
                   __ASM_CFI(".cfi_offset 24,-0x88\n\t")
                   __ASM_CFI(".cfi_offset 25,-0x80\n\t")
                   __ASM_CFI(".cfi_offset 26,-0x78\n\t")
                   __ASM_CFI(".cfi_offset 27,-0x70\n\t")
                   __ASM_CFI(".cfi_offset 28,-0x68\n\t")
                   "bl " __ASM_NAME("abort_thread") )


/***********************************************************************
 *           KeUserModeCallback
 */
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = (frame->sp - offsetof( struct callback_stack_layout, args_data[len] ) - 16) & ~15;
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;

    stack->args = stack->args_data;
    stack->len  = len;
    stack->id   = id;
    stack->lr   = frame->lr;
    stack->sp   = frame->sp;
    stack->pc   = frame->pc;
    memcpy( stack->args_data, args, len );
    {
        /* Thing B (#16) diag: which dispatcher does this thread's callback
         * resolve to? A SESSION-peb thread resolving to a child's EC
         * dispatcher is the wedge precursor (explorer executing the child
         * EC ntdll's exit thunks → blr x16=1). Log the first few callbacks
         * per boot for context plus EVERY session-thread/child-dispatcher
         * cross-resolution (should never happen). */
        extern PEB *peb;
        void *disp = IOS_PFUNC(KiUserCallbackDispatcher);
        int cross = (disp != pKiUserCallbackDispatcher) && (NtCurrentTeb()->Peb == peb);
        static volatile int kcb_logged = 0;
        if ((kcb_logged < 5 || cross) && kcb_logged < 40)
        {
            __sync_add_and_fetch(&kcb_logged, 1);
            dprintf(2, "[kcb] tid=%04x teb=%p peb=%p id=%u disp=%p session_disp=%p%s\n",
                    (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                    (void *)NtCurrentTeb(), (void *)NtCurrentTeb()->Peb, id,
                    disp, pKiUserCallbackDispatcher,
                    cross ? "  <-- SESSION THREAD, CHILD DISPATCHER (BUG)" : "");
        }
        return call_user_mode_callback( sp, ret_ptr, ret_len, disp, NtCurrentTeb() );
    }
}


/***********************************************************************
 *           NtCallbackReturn  (NTDLL.@)
 */
NTSTATUS WINAPI NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    if (!get_syscall_frame()->prev_frame) return STATUS_NO_CALLBACK_ACTIVE;
    user_mode_callback_return( ret_ptr, ret_len, status, NtCurrentTeb() );
}


/***********************************************************************
 *           handle_syscall_fault
 *
 * Handle a page fault happening during a system call.
 */
static BOOL handle_syscall_fault( ucontext_t *context, EXCEPTION_RECORD *rec )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD i;

    if (!is_inside_syscall( SP_sig(context) )) return FALSE;

    TRACE( "code=%x flags=%x addr=%p pc=%p tid=%04x\n",
           rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
           (void *)PC_sig(context), GetCurrentThreadId() );
    for (i = 0; i < rec->NumberParameters; i++)
        TRACE( " info[%d]=%016lx\n", i, rec->ExceptionInformation[i] );

    TRACE("  x0=%016lx  x1=%016lx  x2=%016lx  x3=%016lx\n",
          (DWORD64)REGn_sig(0, context), (DWORD64)REGn_sig(1, context),
          (DWORD64)REGn_sig(2, context), (DWORD64)REGn_sig(3, context) );
    TRACE("  x4=%016lx  x5=%016lx  x6=%016lx  x7=%016lx\n",
          (DWORD64)REGn_sig(4, context), (DWORD64)REGn_sig(5, context),
          (DWORD64)REGn_sig(6, context), (DWORD64)REGn_sig(7, context) );
    TRACE("  x8=%016lx  x9=%016lx x10=%016lx x11=%016lx\n",
          (DWORD64)REGn_sig(8, context), (DWORD64)REGn_sig(9, context),
          (DWORD64)REGn_sig(10, context), (DWORD64)REGn_sig(11, context) );
    TRACE(" x12=%016lx x13=%016lx x14=%016lx x15=%016lx\n",
          (DWORD64)REGn_sig(12, context), (DWORD64)REGn_sig(13, context),
          (DWORD64)REGn_sig(14, context), (DWORD64)REGn_sig(15, context) );
    TRACE(" x16=%016lx x17=%016lx x18=%016lx x19=%016lx\n",
          (DWORD64)REGn_sig(16, context), (DWORD64)REGn_sig(17, context),
          (DWORD64)REGn_sig(18, context), (DWORD64)REGn_sig(19, context) );
    TRACE(" x20=%016lx x21=%016lx x22=%016lx x23=%016lx\n",
          (DWORD64)REGn_sig(20, context), (DWORD64)REGn_sig(21, context),
          (DWORD64)REGn_sig(22, context), (DWORD64)REGn_sig(23, context) );
    TRACE(" x24=%016lx x25=%016lx x26=%016lx x27=%016lx\n",
          (DWORD64)REGn_sig(24, context), (DWORD64)REGn_sig(25, context),
          (DWORD64)REGn_sig(26, context), (DWORD64)REGn_sig(27, context) );
    TRACE(" x28=%016lx  fp=%016lx  lr=%016lx  sp=%016lx\n",
          (DWORD64)REGn_sig(28, context), (DWORD64)FP_sig(context),
          (DWORD64)LR_sig(context), (DWORD64)SP_sig(context) );

    if (ntdll_get_thread_data()->jmp_buf)
    {
        TRACE( "returning to handler\n" );
        REGn_sig(0, context) = (ULONG_PTR)ntdll_get_thread_data()->jmp_buf;
        REGn_sig(1, context) = 1;
        PC_sig(context)      = (ULONG_PTR)longjmp;
        ntdll_get_thread_data()->jmp_buf = NULL;
    }
    else
    {
        TRACE( "returning to user mode ip=%p ret=%08x\n", (void *)frame->pc, rec->ExceptionCode );
        REGn_sig(0, context)  = rec->ExceptionCode;
        REGn_sig(18, context) = (ULONG_PTR)NtCurrentTeb();
        SP_sig(context)       = (ULONG_PTR)frame;
        PC_sig(context)       = (ULONG_PTR)__wine_syscall_dispatcher_return;
    }
    return TRUE;
}


/**********************************************************************
 *		ios_fixup_x18_for_return
 *
 * Called before returning from a signal handler on iOS.
 * iOS sigreturn zeroes x18 (the TEB/platform register).  If the
 * interrupted code was in the JIT pool, redirect through the TEB
 * trampoline so x18 is restored before the code resumes.
 */
#ifdef WINE_IOS
static inline void ios_fixup_x18_for_return( ucontext_t *context )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;

    if (!ios_my_trampoline || !ios_teb_for_signals) return;

    uintptr_t pc = PC_sig(context);
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    size_t sz = ios_jit_pool_size_global;

    if (rx && pc >= rx && pc < rx + sz)
    {
        REGn_sig(17, context) = pc;
        PC_sig(context) = (uintptr_t)ios_my_trampoline;
    }
}

static inline void ios_track_signal( int sig, ucontext_t *context )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    ios_signal_total++;
    ios_signal_last = sig;
    uintptr_t pc = PC_sig(context);
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    size_t sz = ios_jit_pool_size_global;
    if (rx && pc >= rx && pc < rx + sz)
        ios_signal_in_pe++;
}

#endif


/**********************************************************************
 *		segv_handler
 *
 * Handler for SIGSEGV.
 */
static int dumped_page0;   /* ml180: one wide dump, for the page-0 fault only */

/* ml174: is a candidate FEX CpuStateFrame initialised? See the call site. */
static int probe_ptr_ok( uint64_t frame )
{
    uint64_t v = 0;
    mach_vm_size_t g = 0;

    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(frame + 0x40), 8,
                                (mach_vm_address_t)&v, &g ) != KERN_SUCCESS || g != 8)
        return 0;
    return v >= 0x100000000ull && v < 0x8000000000ull;
}

static void segv_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    DWORD64 esr = get_fault_esr( context );

#ifdef WINE_IOS
    ios_track_signal( signal, context );
    {
        static int segv_dump_count = 0;
        static int total_segv_count = 0;
        total_segv_count++;
        ios_total_segv_count = total_segv_count;
        void *pc = (void*)PC_sig(context);

        /* Read the NATIVE x18 (iOS platform register value in handler context) */
        uint64_t native_x18;
        __asm__ volatile("mov %0, x18" : "=r"(native_x18));

        /* Log first few SEGVs with both native and ucontext x18 */
        if (total_segv_count <= 5)
            ERR("SEGV #%d: pc=%p addr=%p uctx_x18=%p disp=%llu mach_exc=%d\n",
                total_segv_count, pc, siginfo->si_addr,
                (void*)REGn_sig(18, context),
                (unsigned long long)g_wine_dispatcher_count,
                ios_exc_msg_count);

        /* Execution fault at PE address → redirect to JIT pool */
        if (pc == siginfo->si_addr)
        {
            extern void *ios_jit_translate_addr(void *addr);
            void *jit_pc = ios_jit_translate_addr(pc);
            if (jit_pc != pc)
            {
                /* Use trampoline to set x18 (sigreturn zeroes it on iOS) */
                if (ios_my_trampoline && ios_teb_for_signals)
                {
                    REGn_sig(17, context) = (uintptr_t)jit_pc;
                    PC_sig(context) = (uintptr_t)ios_my_trampoline;
                }
                else
                {
                    PC_sig(context) = (uintptr_t)jit_pc;
                }
                return;
            }
        }

        /* Redirect user_shared_data accesses (0x7FFE0000) to our real allocation.
         * iOS __PAGEZERO prevents mapping at the standard Windows address.
         * Find the register holding 0x7FFE* and replace with real address. */
        {
            uintptr_t fault_addr = (uintptr_t)siginfo->si_addr;
            if (fault_addr >= 0x7FFE0000 && fault_addr < 0x7FFF0000)
            {
                extern struct _KUSER_SHARED_DATA *user_shared_data;
                uintptr_t real_usd = (uintptr_t)user_shared_data;
                if (real_usd && real_usd != 0x7FFE0000)
                {
                    int fixed = 0;
                    for (int reg = 0; reg <= 28; reg++)
                    {
                        uint64_t rval = REGn_sig(reg, context);
                        if (rval >= 0x7FFE0000 && rval < 0x7FFF0000)
                        {
                            REGn_sig(reg, context) = real_usd + (rval - 0x7FFE0000);
                            fixed = 1;
                        }
                    }
                    if (fixed)
                    {
                        static int usd_fix_count = 0;
                        if (usd_fix_count < 10)
                            ERR("USD redirect: addr=%p → real_usd=%p (fix #%d)\n",
                                (void*)fault_addr, (void*)real_usd, usd_fix_count);
                        usd_fix_count++;

                        /* Also fix x18 if zeroed, and route through trampoline */
                        extern void *ios_jit_rw_base_global;
                        if (REGn_sig(18, context) == 0 && ios_teb_for_signals && ios_my_trampoline)
                        {
                            if (ios_jit_rw_base_global && ios_my_slot >= 0)
                                *(uint64_t *)((char *)ios_jit_rw_base_global + ios_my_slot * 16) = ios_teb_for_signals;
                            REGn_sig(17, context) = PC_sig(context);
                            PC_sig(context) = (uintptr_t)ios_my_trampoline;
                        }
                        return;
                    }
                }
            }
        }

        /* If x18 is 0 and we have TEB backup, restore it directly.
         * iOS kernel zeroes x18 (platform register) on signal delivery.
         * The binary patcher is the real fix (rewrites x18 refs to use
         * a safe TEB load sequence). This is just a simple fallback.
         *
         * BUT: if the faulting PC is itself in low/unmapped memory (i.e. we
         * jumped to an unrelocated RVA), restoring x18 doesn't help — the
         * next SEGV will fire at the same PC. Fall through to the diagnostic
         * dump so the real cause is visible.
         *
         * AND (2026-07-06): only retry when the faulting instruction's base
         * register IS x18 (Rn==18, the same discriminator the Mach handler's
         * [x18,#imm] emulation uses). A fault with any other base register is
         * NOT x18-caused — retrying it swallows genuine guest access
         * violations in an infinite loop (Thumper desktop: `ldrh w7,[x7,...]`
         * on guest pointer 0x3f800018 = float 1.0 bits spun 6.8M times here
         * instead of being delivered to the game as an AV). */
        /* ml158 PROBE (#36): the webhelper dies on a fault this discriminator
         * declines. ml157 showed FEX emitted `movz w1,#0; ldr x1,[x1]` — the
         * page-0 address was materialised into a SCRATCH register, so Rn!=18
         * and we fall through to a fatal SEGV (5 repeats -> thread exit ->
         * steam exit(1)).
         *
         * ml158 note: the first cut of this probe went into the MACH handler,
         * but these faults arrive via segv_handler (this function), so it
         * never fired. Same probe, correct handler.
         *
         * Open question this answers: is address 0 here a TEB offset FEX
         * spilled to a scratch reg, or a genuine guest NULL deref? Emulating
         * the wrong one silently corrupts, so DO NOT widen the discriminator
         * until this says which. An x18 spill (`mov xN,x18`) in the preceding
         * instructions => TEB access; a guest-address computation => real NULL
         * deref (cf. the Thumper 0x3f800018 case that motivated Rn==18). */
        /* ml165 (#36): RECOVER A NULL FEX STATE REGISTER (x28).
         *
         * Report #1 caught `ldr w2,[x28,#0x5d0]` faulting with x28 == 0, inside a
         * function whose prologue is `... mov x28, x0` — so FEX was ENTERED with a NULL
         * CpuStateFrame in arg0 and propagated it into STATE. Surrounding registers place
         * it mid-PartitionAlloc-reservation (x27 == 0x400010000, exactly our jumbo pool
         * size; x21/x22 look like PA hints).
         *
         * The authoritative frame pointer is available and provably correct: the CPU area
         * at TEB+0x1788 holds it at +0x30 (FEX sets CPUArea->SuspendDoorbell from the same
         * frame at Module.cpp:1443), and in the SAME process/TEB of ml165 reports #3/#4
         * carried x28 == 0x7310001140 == CPUArea+0x30. So restoring x28 from CPUArea+0x30
         * and retrying restores exactly the value FEX itself would have used.
         *
         * This mirrors the accepted x18-restore-from-TSD-275 approach. Gated hard, because
         * x28 is an ordinary callee-saved register in non-FEX code and ALL our modules run
         * from the JIT pool:
         *   - x28 must be EXACTLY 0 (not merely small),
         *   - the faulting instruction's base register must BE x28,
         *   - the fault offset must be a plausible CpuStateFrame field (< 64KB),
         *   - CPUArea+0x30 must read back non-NULL, and the target field must be readable.
         * Reads go through mach_vm_read_overwrite so a bad CPU area cannot recurse the
         * handler. pc is NOT advanced: we fix the register and re-execute.
         *
         * If this restores the wrong thing we will see it immediately — the fault was
         * fatal anyway, so recovery is strictly better than dying, and every restore is
         * logged. */
        if (REGn_sig(28, context) == 0 && (uintptr_t)pc >= 0x100000000ULL
            && ios_teb_for_signals != 0)
        {
            uintptr_t fa = (uintptr_t)siginfo->si_addr;
            uint32_t insn = *(uint32_t *)pc;

            if (((insn >> 5) & 31) == 28 && fa < 0x10000)
            {
                uint64_t cpu_area = 0, frame = 0, probe = 0;
                mach_vm_size_t got = 0;

                if (mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(ios_teb_for_signals + 0x1788), 8,
                        (mach_vm_address_t)&cpu_area, &got ) == KERN_SUCCESS && got == 8
                    && cpu_area
                    && mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(cpu_area + 0x30), 8,
                        (mach_vm_address_t)&frame, &got ) == KERN_SUCCESS && got == 8
                    && frame
                    && mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(frame + fa), 8,
                        (mach_vm_address_t)&probe, &got ) == KERN_SUCCESS && got == 8
                    /* ml174: the frame must also be INITIALISED, not merely readable.
                     * Restoring a readable-but-uninitialised frame is worse than not
                     * restoring at all: in ml174 x28 was set to 0x7c80001140 and the very
                     * next instruction did `ldr x2,[x28,#0x40]` -> garbage -> `str x0,[x2]`
                     * faulted at 0x80001131, and the bogus exception frame turned a
                     * contained thread-kill into "frame not in stack limits" and killed
                     * the whole process. FEX keeps a pointer at frame+0x40 (the sequence
                     * ldr/sub #0x10/str/store-through is a stack-style push), so require
                     * it to look like a real userspace pointer before trusting the frame. */
                    && probe_ptr_ok( frame ))
                {
                    static int ios_state_restores;

                    if (ios_state_restores < 12)
                    {
                        ios_state_restores++;
                        ERR( "[state-restore] #%d pc=%p insn=%08x off=0x%lx x28=0 -> %p "
                             "(CPUArea=%p) retrying\n", ios_state_restores, pc, insn,
                             (unsigned long)fa, (void *)(uintptr_t)frame,
                             (void *)(uintptr_t)cpu_area );
                    }
                    REGn_sig(28, context) = frame;
                    return;
                }
            }
        }

        {
            uintptr_t f_addr = (uintptr_t)siginfo->si_addr;
            uint32_t f_insn = ((uintptr_t)pc >= 0x100000000ULL) ? *(uint32_t *)pc : 0;
            int f_rn = (f_insn >> 5) & 31;
            static int ios_x18_decline_reports;

            if (REGn_sig(18, context) == 0 && ios_teb_for_signals != 0
                && (uintptr_t)pc >= 0x100000000ULL && f_addr < 0x10000
                && f_rn != 18 && ios_x18_decline_reports < 4)
            {
                const uint32_t *w = (const uint32_t *)pc;
                char buf[512];
                int n = 0, k;
                ios_x18_decline_reports++;
                for (k = -16; k <= 4 && n < (int)sizeof(buf) - 16; k++)
                    n += snprintf( buf + n, sizeof(buf) - n, "%s%08x",
                                   (k == -16) ? " [" : " ", w[k] );
                snprintf( buf + n, sizeof(buf) - n, "]" );
                ERR("[x18-decline] #%d pc=%p fault_addr=0x%lx insn=%08x rn=%d "
                    "xRn=%p (rn_val==fault_addr? %d) x18=0 teb=%p\n",
                    ios_x18_decline_reports, pc, (unsigned long)f_addr, f_insn, f_rn,
                    (void *)REGn_sig(f_rn, context),
                    (uintptr_t)REGn_sig(f_rn, context) == f_addr,
                    (void *)ios_teb_for_signals);
                ERR("[x18-decline] #%d insns pc-64..pc+16:%s\n",
                    ios_x18_decline_reports, buf);

                /* ml164 follow-up: 21 instruction words were not enough to NAME the
                 * emitted stub, and source archaeology has not pinned it either. Scan a
                 * wide window for STRUCTURAL markers whose encodings are unambiguous, so
                 * the stub identifies itself:
                 *
                 *   brk #0xCAFE = 0xd4395fc0  -> Arm64JITCore::EmitSuspendInterruptCheck
                 *                                (SuspendMagic; ARCHITECTURE_arm64ec only)
                 *   brk #0x0    = 0xd4200000  -> generic trap
                 *   mrs xN, TPIDRRO_EL0 (0xd53bd060 mask) -> IOS_LOAD_TEB / x18 patcher
                 *                                trampoline, i.e. a TEB-load site
                 *   msr TPIDR_EL0 (0xd51bd040 mask) -> MUST NEVER appear (corrupts Apple
                 *                                malloc); flag loudly if it does.
                 *
                 * Read through mach_vm_read_overwrite, never a raw deref: pc may sit near
                 * the start of its mapping and a fault inside this handler would recurse. */
                {
                    static uint32_t win[320];   /* pc-1024 .. pc+256 */
                    mach_vm_size_t got = 0;
                    uintptr_t base = (uintptr_t)pc - 1024;

                    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)base,
                                                sizeof(win), (mach_vm_address_t)win,
                                                &got ) == KERN_SUCCESS && got >= 4)
                    {
                        unsigned words = (unsigned)(got / 4), j;
                        int cafe = -1, brk0 = -1, tpidrro = -1, tpidrw = -1;

                        for (j = 0; j < words; j++)
                        {
                            uint32_t v = win[j];
                            int off = (int)(j * 4) - 1024;
                            if (v == 0xd4395fc0 && cafe < 0) cafe = off;
                            else if (v == 0xd4200000 && brk0 < 0) brk0 = off;
                            if ((v & 0xffffffe0) == 0xd53bd060 && tpidrro < 0) tpidrro = off;
                            if ((v & 0xffffffe0) == 0xd51bd040 && tpidrw < 0) tpidrw = off;
                        }
                        ERR("[x18-decline] #%d markers(words=%u): brk#CAFE@%d brk#0@%d "
                            "mrs_TPIDRRO@%d msr_TPIDR_EL0@%d%s\n",
                            ios_x18_decline_reports, words, cafe, brk0, tpidrro, tpidrw,
                            tpidrw >= 0 ? "  <-- ILLEGAL TPIDR_EL0 WRITE IN THIS BLOCK" : "");

                        /* ml179: the fault is ALWAYS at offset 0x650 of a 16KB-aligned
                         * block, and FEX's whole generated dispatcher is exactly
                         * MAX_DISPATCHER_CODE_SIZE = FEX_PAGE_SIZE*4 = 16KB
                         * (Dispatcher.cpp:48). So this pc is a FIXED location in the
                         * dispatcher, and 21 instruction words were never going to name
                         * it. Dump a wide raw window instead so it can be disassembled
                         * offline against Dispatcher.cpp's emission order — that is what
                         * finally identifies the stub, with no FEX rebuild.
                         * Emitted as 8 lines of 16 words to stay readable. */
                        /* ml180: gate on the PAGE-0 fault, not on report #1. The
                         * first qualifying fault in a run is often the NULL-CS one
                         * (RtlLeaveCriticalSection, addr=0x8), which consumed the single
                         * dump last run and told us nothing about the FEX site. Also drop
                         * the "dispatcher is 16KB" wording: 16KB-alignment of the pc is
                         * arithmetic, not evidence that the block IS FEX's dispatcher. */
                        /* ml191 CALLRET PROBE. The two guest RIPs that reach this
                         * trampoline are libcef+0x1900733 and +0x3b508f0. Decoding libcef
                         * forward from 0x1900733-16 gives a clean x86 stream
                         * (mov/mov/test/je/mov/call) in which the `call` STARTS ONE BYTE
                         * BEFORE that RIP — i.e. the guest arrived MID-INSTRUCTION. FEX
                         * then decodes garbage and raises NoExecOp (PARTIAL_DECODE_INST
                         * routes to the same handler as NOEXEC_INST), which is why this
                         * looked like a permissions bug when it is really a bad control
                         * flow target.
                         *
                         * So log where the target came from: FEX's call-return prediction
                         * stack. The ml174 dump showed the push sequence
                         *   ldr x2,[x28,#0x40]; sub x2,#0x10; str x2,[x28,#0x40]; str x0,[x2]
                         * ml193: the first cut guessed frame+0x40/+0x48 from that push and
                         * was WRONG — the probe self-reported it (in_range=0, and the
                         * "entries" decoded as ASCII text), which is exactly why it was
                         * built to validate. Offsets now COMPUTED from CPUState in
                         * CoreState.h rather than inferred:
                         *   +0x00 InlineJITBlockHeader, +0x08 DeferredSignalRefCount,
                         *   +0x10 pf_raw, +0x14 af_raw, +0x18 rip,
                         *   +0x20 gregs[16] (128B, ..0x9F), +0xA0 L1Pointer, +0xA8 L1Mask,
                         *   +0xB0 callret_sp, +0xB8 callret_sp_base
                         * CPUState is the first member of CpuStateFrame, so these are
                         * frame-relative. (+0x18 rip also matches the known state[0x18]
                         * native-PC note.) */
                        if (f_addr == 0 && REGn_sig(28, context) >= 0x100000000ULL)
                        {
                            uint64_t frame = REGn_sig(28, context);
                            uint64_t sp = 0, base = 0, ent[8] = {0};
                            mach_vm_size_t g = 0;
                            int ok_sp, ok_base, ok_ent = 0;

                            ok_sp = (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(frame + 0xB0), 8,
                                        (mach_vm_address_t)&sp, &g ) == KERN_SUCCESS && g == 8);
                            ok_base = (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(frame + 0xB8), 8,
                                        (mach_vm_address_t)&base, &g ) == KERN_SUCCESS && g == 8);
                            if (ok_sp && sp >= 0x10000)
                                ok_ent = (mach_vm_read_overwrite( mach_task_self(),
                                            (mach_vm_address_t)sp, sizeof(ent),
                                            (mach_vm_address_t)ent, &g ) == KERN_SUCCESS);
                            {
                                uint64_t grip = 0; mach_vm_size_t g2 = 0;
                                if (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(frame + 0x18), 8,
                                        (mach_vm_address_t)&grip, &g2 ) == KERN_SUCCESS)
                                    ERR("[callret] State.rip=%p\n", (void *)(uintptr_t)grip);
                            }
                            ERR("[callret] frame=%p sp=%p(ok=%d) base=%p(ok=%d) in_range=%d\n",
                                (void *)(uintptr_t)frame, (void *)(uintptr_t)sp, ok_sp,
                                (void *)(uintptr_t)base, ok_base,
                                (ok_sp && ok_base && base && sp >= base && sp < base + 0x1000000));
                            if (ok_ent)
                                ERR("[callret] top: %llx %llx %llx %llx %llx %llx %llx %llx\n",
                                    (unsigned long long)ent[0], (unsigned long long)ent[1],
                                    (unsigned long long)ent[2], (unsigned long long)ent[3],
                                    (unsigned long long)ent[4], (unsigned long long)ent[5],
                                    (unsigned long long)ent[6], (unsigned long long)ent[7]);
                        }

                        if (f_addr == 0 && !dumped_page0 && (dumped_page0 = 1))
                        {
                            uintptr_t blk = (uintptr_t)pc & ~0x3fffULL;
                            unsigned row;

                            ERR("[disp-dump] block=%p pc=%p offset=0x%lx (16KB-aligned window)\n",
                                (void *)blk, pc, (unsigned long)((uintptr_t)pc - blk));
                            for (row = 0; row < 8; row++)
                            {
                                /* window: pc-0x200 .. pc+0x0 , 16 words per row */
                                const uint32_t *w2 = (const uint32_t *)((uintptr_t)pc - 0x200 + row * 64);
                                int off = -0x200 + (int)(row * 64);
                                char lb[256];
                                int ln = 0, q;
                                for (q = 0; q < 16 && ln < (int)sizeof(lb) - 12; q++)
                                    ln += snprintf( lb + ln, sizeof(lb) - ln, "%08x ",
                                                    win[(0x400 + off + q * 4) / 4] );
                                (void)w2;
                                ERR("[disp-dump] +%04x: %s\n",
                                    (unsigned)((uintptr_t)pc - blk + off), lb);
                            }
                        }
                    }
                    else
                        ERR("[x18-decline] #%d marker scan unreadable at %p\n",
                            ios_x18_decline_reports, (void *)base);
                }

                /* ml159 follow-up: the fatal webhelper fault is FEX's own
                 * `movz w1,#0; ldr x1,[x1]` sitting between two
                 * SpillStaticRegs (verified against Arm64Emitter.cpp: the
                 * trailing mrs FPCR / bic NEP|AH|FIZ / msr FPCR is literally
                 * SpillStaticRegs' first emission). Probe #2 showed FEX's
                 * STATE register x28 == 0 in this process. The segv dump
                 * prints x0-x3/x8-x10/x16-x20 but NOT x21-x28, so we cannot
                 * yet tell whether the fatal site ALSO has a null STATE.
                 *
                 * FEX spills guest regs to [x28,#N] and FPRs via x10=x28+0x1c0
                 * — so if x28 is sane here, the null pointer is a separate
                 * FEX constant; if x28 is 0, the whole FEX instance is
                 * uninitialised and the fix belongs in FEX per-process init.
                 * Also walk TEB -> CPUArea (TEB+0x1788) -> +0x30, the chain
                 * the EC dispatcher uses, since that is what FEX_IOS_HOST
                 * reads via TPIDRRO_EL0 + TSD slot 275. */
                ERR("[x18-decline] #%d x21=%p x22=%p x23=%p x24=%p\n",
                    ios_x18_decline_reports,
                    (void *)REGn_sig(21, context), (void *)REGn_sig(22, context),
                    (void *)REGn_sig(23, context), (void *)REGn_sig(24, context));
                ERR("[x18-decline] #%d x25=%p x26=%p x27=%p x28(STATE)=%p lr=%p sp=%p\n",
                    ios_x18_decline_reports,
                    (void *)REGn_sig(25, context), (void *)REGn_sig(26, context),
                    (void *)REGn_sig(27, context), (void *)REGn_sig(28, context),
                    (void *)REGn_sig(30, context), (void *)SP_sig(context));
                {
                    /* Read via mach_vm_read_overwrite, never a raw deref: a
                     * fault INSIDE the segv handler would recurse and hang
                     * the app instead of dying cleanly. */
                    uintptr_t teb = ios_teb_for_signals;
                    uint64_t cpu_area = 0, ca30 = 0;
                    mach_vm_size_t got = 0;
                    int ok1 = 0, ok2 = 0;

                    if (teb)
                        ok1 = (mach_vm_read_overwrite( mach_task_self(),
                                   (mach_vm_address_t)(teb + 0x1788), 8,
                                   (mach_vm_address_t)&cpu_area, &got ) == KERN_SUCCESS
                               && got == 8);
                    if (ok1 && cpu_area)
                        ok2 = (mach_vm_read_overwrite( mach_task_self(),
                                   (mach_vm_address_t)(cpu_area + 0x30), 8,
                                   (mach_vm_address_t)&ca30, &got ) == KERN_SUCCESS
                               && got == 8);
                    ERR("[x18-decline] #%d teb=%p CPUArea(teb+0x1788)=%p(ok=%d) "
                        "CPUArea+0x30=%p(ok=%d)\n",
                        ios_x18_decline_reports, (void *)teb,
                        (void *)(uintptr_t)cpu_area, ok1,
                        (void *)(uintptr_t)ca30, ok2);
                }
            }
        }

        if (REGn_sig(18, context) == 0 && ios_teb_for_signals != 0
            && (uintptr_t)pc >= 0x100000000ULL
            && ((*(uint32_t *)pc >> 5) & 31) == 18)
        {
            REGn_sig(18, context) = ios_teb_for_signals;
            return;
        }

        if (segv_dump_count < 20)
        {
            segv_dump_count++;
            /* Check TPIDR_EL0 — should hold TEB if binary patcher is working */
            uint64_t tpidr_el0;
            __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(tpidr_el0));
            /* ml209: TPIDR_EL0 is INFORMATIONAL ONLY. iOS owns and zeroes it, we removed
             * our `msr TPIDR_EL0, x18` on 2026-07-04, and nothing of ours reads it — TEB
             * recovery runs off TPIDRRO_EL0 + TSD slot 275, printed below. The old
             * "(expected ...)" wording cost a debugging detour by making a garbage value
             * here look like a root cause; it is not one. */
            ERR("SEGV at pc=%p addr=%p esr=0x%llx TPIDR_EL0=%p (informational only — TEB is tsd275 below)\n",
                pc, siginfo->si_addr, (unsigned long long)esr, (void*)tpidr_el0);
            ERR("  x0=%p x1=%p x2=%p x3=%p\n",
                (void*)REGn_sig(0, context), (void*)REGn_sig(1, context),
                (void*)REGn_sig(2, context), (void*)REGn_sig(3, context));
            ERR("  x8=%p x9=%p x10=%p x16=%p x17=%p x18=%p x19=%p x20=%p\n",
                (void*)REGn_sig(8, context),
                (void*)REGn_sig(9, context), (void*)REGn_sig(10, context),
                (void*)REGn_sig(16, context), (void*)REGn_sig(17, context),
                (void*)REGn_sig(18, context), (void*)REGn_sig(19, context),
                (void*)REGn_sig(20, context));
            ERR("  fp=%p lr=%p sp=%p\n",
                (void*)FP_sig(context), (void*)REGn_sig(30, context),
                (void*)SP_sig(context));
            /* task #24: settings threads fault in the TSD-275 thunk with a
             * NULL slot despite start_thread's write. Dump the live slot +
             * base at fault time, and dladdr any dyld-cache pc/lr so Apple
             * frames name themselves. */
            {
                extern pthread_key_t ios_teb_tls_key;
                uintptr_t tsd_base_now;
                __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base_now));
                tsd_base_now &= ~7ULL;
                ERR("  [tsd275] base=%p slot275=%p teb_key_val=%p\n",
                    (void*)tsd_base_now, *(void **)(tsd_base_now + 275 * 8),
                    pthread_getspecific(ios_teb_tls_key));
            }
            /* ml209: the libcef-init wall. A guest PUSH faulted writing to an address
             * Wine does not own, because the guest RSP held 0x40001141 while the thread's
             * real stack was [73d2130000..73d2170000]. The faulting block was
             *   ldr x2,[x28,#0x40] / sub x2,x2,#0x10 / str x2,[x28,#0x40] / str x0,[x2]
             * so x28 is FEX's live STATE pointer and +0x40 is gregs[4] = RSP.
             *
             * Dump the whole CPUState to split the two candidates, which need opposite
             * fixes: if only RSP is implausible the guest clobbered its own stack pointer;
             * if most gregs are garbage we are executing on an uninitialised or wrong
             * CpuStateFrame. The plausible-pointer count is the discriminator, and it is
             * printed alongside the raw values so a wrong assumption here is visible
             * rather than silently believed. */
            {
                uint64_t state = REGn_sig(28, context);
                uint64_t cs[17];              /* +0x18 rip, then gregs[0..15] */
                mach_vm_size_t got = 0;

                if (state && mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(state + 0x18), sizeof(cs),
                        (mach_vm_address_t)cs, &got ) == KERN_SUCCESS && got == sizeof(cs))
                {
                    static const char * const gn[16] = {
                        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                        "r8 ","r9 ","r10","r11","r12","r13","r14","r15" };
                    int i, plausible = 0;

                    ERR("  [guest-state] x28=%p rip=%p\n", (void*)state, (void*)cs[0]);
                    for (i = 0; i < 16; i += 4)
                        ERR("  [guest-state]   %s=%p %s=%p %s=%p %s=%p\n",
                            gn[i],   (void*)cs[1+i], gn[i+1], (void*)cs[2+i],
                            gn[i+2], (void*)cs[3+i], gn[i+3], (void*)cs[4+i]);
                    for (i = 0; i < 16; i++)
                        if (cs[1+i] >= 0x100000000ull && cs[1+i] < 0x8000000000ull) plausible++;
                    ERR("  [guest-state] plausible-ptr gregs=%d/16 (low => uninitialised frame, "
                        "high => only rsp clobbered)\n", plausible);

                    /* ml212: NAME THE CALLER.
                     *
                     * The guest RIP is <arena>+0xe0080 — an address with no code — so FEX
                     * raised SIGSEGV through its deliberate `mov w1,#0; ldr x1,[x1]`
                     * trampoline (visible in insn_stream above). Nothing is corrupt: the
                     * CpuStateFrame is valid and the fault is FEX correctly reporting a
                     * bogus branch target. The open question is who branched there, and
                     * that offset has been byte-identical across runs and across three
                     * different arena bases, so it is computed, not random.
                     *
                     * FEX keeps guest return addresses on its callret stack
                     * (CPUState+0xB0 = sp, +0xB8 = base). Dump the top entries; resolving
                     * them offline against the [iOS-xins]/[jit-pool] bases names the
                     * function that jumped. Depth is printed too, so an empty or absurd
                     * stack is visible rather than silently mistaken for evidence. */
                    {
                        uint64_t cr[2] = { 0, 0 };
                        uint64_t ents[8];
                        mach_vm_size_t g2 = 0;

                        if (mach_vm_read_overwrite( mach_task_self(),
                                (mach_vm_address_t)(state + 0xB0), sizeof(cr),
                                (mach_vm_address_t)cr, &g2 ) == KERN_SUCCESS && g2 == sizeof(cr))
                        {
                            unsigned long long depth =
                                (cr[0] > cr[1]) ? (cr[0] - cr[1]) / 8 : 0;

                            ERR("  [callret] sp=%p base=%p depth=%llu\n",
                                (void *)cr[0], (void *)cr[1], depth );

                            /* ml213: the cap was 0x100000, but a real run had depth=168218
                             * (1.28MB of stack) and the dump was skipped for no good
                             * reason — only the TOP n*8 bytes are ever read, so the total
                             * size never mattered. Bound it generously, purely as a
                             * sanity check against a garbage sp/base pair. */
                            if (depth && cr[0] - cr[1] <= 0x10000000)
                            {
                                unsigned n = depth > 8 ? 8 : (unsigned)depth;

                                if (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(cr[0] - (uint64_t)n * 8),
                                        n * 8, (mach_vm_address_t)ents, &g2 ) == KERN_SUCCESS
                                    && g2 == n * 8)
                                {
                                    unsigned k;

                                    for (k = n; k-- > 0; )
                                        ERR("  [callret]   [-%u] %p\n", n - k, (void *)ents[k]);
                                }
                            }
                        }
                    }
                }
                else
                    ERR("  [guest-state] x28=%p UNREADABLE got=%llu\n",
                        (void*)state, (unsigned long long)got);
            }
            {
                uintptr_t sym_addrs[2] = { (uintptr_t)PC_sig(context), (uintptr_t)REGn_sig(30, context) };
                int si;
                for (si = 0; si < 2; si++)
                {
                    Dl_info di_s;
                    const char *img_s;
                    if (sym_addrs[si] >= 0x180000000ULL && (sym_addrs[si] >> 32) < 0x300 &&
                        dladdr((void *)sym_addrs[si], &di_s) && di_s.dli_sname)
                    {
                        img_s = di_s.dli_fname ? strrchr(di_s.dli_fname, '/') : NULL;
                        img_s = img_s ? img_s + 1 : (di_s.dli_fname ? di_s.dli_fname : "?");
                        ERR("  [sym] %s=%s`%s+0x%llx\n", si ? "lr" : "pc", img_s,
                            di_s.dli_sname,
                            (unsigned long long)(sym_addrs[si] - (uintptr_t)di_s.dli_saddr));
                    }
                }
            }
            if ((uintptr_t)PC_sig(context) >= 0x100000000ULL)
            {
                uint32_t *p = (uint32_t*)(uintptr_t)PC_sig(context);
                /* ml265 (#46): WIDE window when the fault PC is FEX-emitted code.
                 *
                 * The ml265 fatal is a DELIBERATE null deref in the dispatcher:
                 *   52800001  movz w1, #0        <- x1 set to 0 literally
                 *   f9400021  ldr  x1, [x1]      <- FAULTS
                 *   d53b440a  mrs  x10, fpcr     (FP-control setup)
                 * preceded by two `st1` SIMD stores -- the dispatcher's FP-save
                 * sequence. pc sits at pool offset 0x36ff8650, the tail EC_CODE area,
                 * i.e. code FEX EMITTED, not translated guest code.
                 *
                 * That matters because this port already patches "FEX's emitter on iOS
                 * produces garbage words in the dispatcher" (Module.cpp SpillStaticRegs
                 * scanner), whose own comment notes mis-patching "causes st1 faults
                 * later". 7 words is too narrow to tell a genuine emit from a corrupted
                 * one, and the offset relative to the dispatcher decides which documented
                 * site (+0x160 / +0x184 / +0x264) this is. Dump 24 words with the pool
                 * offset so the emitted sequence can be read offline against the
                 * expected layout. Capped; only for pool PCs. */
                {
                    extern void *ios_jit_rx_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uintptr_t rxb = (uintptr_t)ios_jit_rx_base_global;
                    uintptr_t fpc = (uintptr_t)PC_sig(context);
                    static int wide_dumps;

                    if (rxb && fpc >= rxb && fpc < rxb + ios_jit_pool_size_global &&
                        wide_dumps < 4)
                    {
                        const uint32_t *w = (const uint32_t *)(fpc - 48);
                        int i;
                        wide_dumps++;
                        ERR("  [emit-dump] pc=0x%llx pooloff=0x%llx  PC-48..PC+44:\n",
                            (unsigned long long)fpc, (unsigned long long)(fpc - rxb));
                        for (i = 0; i < 24; i += 6)
                            ERR("  [emit-dump]   +%-4d %08x %08x %08x %08x %08x %08x\n",
                                (i - 12) * 4, w[i], w[i+1], w[i+2], w[i+3], w[i+4], w[i+5]);
                    }
                }
                /* ml270 (#48): WHERE does the corrupt guest RSP come from?
                 *
                 * Signature across runs: RSP alone is garbage while the other guest
                 * registers stay valid -- "plausible-ptr gregs=11/16", and the probe's own
                 * legend reads "high => only rsp clobbered". The bad value is structured,
                 * not random:
                 *   ml260 rsp=0x40001131  addr=0x40001131  addr=0xe0001131
                 *   ml270 rsp=0x80001131  addr=0x80001131
                 * low 28 bits constant at 0x0001131, only the TOP NIBBLE varies (4/8/e) --
                 * which is where ARM64 NZCV lives (4=Z, 8=N, e=NZC).
                 *
                 * In ARM64EC guest RSP is SRA register x23, spilled/filled via
                 * State.gregs[RSP]. Three outcomes need different fixes:
                 *   x23 garbage but gregs[RSP] VALID  -> a fill/spill bug clobbered the reg
                 *   both garbage                       -> corruption happened earlier
                 *   top nibble == flags[24] (NZCV)     -> a FLAGS word is being used as RSP
                 * Print all three rather than pattern-matching hex, which has misled before. */
                {
                    static int rspq;
                    /* Get the TEB the same way the [tsd275] dump above does — a POSIX
                     * signal handler has no mach thread_t to hand, and x18 is zero here. */
                    uintptr_t tsd_r;
                    uintptr_t teb_r;
                    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_r));
                    tsd_r &= ~7ULL;
                    teb_r = (uintptr_t)*(void **)(tsd_r + 275 * 8);

                    if (rspq < 6 && teb_r)
                    {
                        void *cpuarea_r = *(void**)(teb_r + 0x1788);
                        if (cpuarea_r)
                        {
                            uint64_t *frame_r = *(uint64_t**)((char*)cpuarea_r + 0x30);
                            if (frame_r)
                            {
                                rspq++;
                                /* ml272: offsets CONFIRMED from FEX's own [state-offsets]
                                 * line -- rip=0x18 gregs=0x20 gregs[RSP]=0x40
                                 * callret_sp=0xb0 callret_sp_base=0xb8 flags=0x3f0.
                                 * The first cut of this probe read gregs[RSP] at 0x28,
                                 * which is gregs[1] = RCX, so every "gregs[RSP]=0" it
                                 * printed was meaningless. Also print callret_sp, since
                                 * the dispatcher's `ldr x17,[x28,#176]` reads exactly
                                 * that field and x17==0 is the #42 storm's trigger. */
                                ERR("  [rsp-forensics] x23(SRA RSP)=%p  gregs[RSP]=%p  "
                                    "NZCV/flags[24]=0x%08x  callret_sp=%p base=%p  x28=%p%s\n",
                                    (void*)(uintptr_t)REGn_sig(23, context),
                                    (void*)(uintptr_t)frame_r[0x40/8],
                                    (unsigned)((uint32_t*)frame_r)[0x408/4],
                                    (void*)(uintptr_t)frame_r[0xb0/8],
                                    (void*)(uintptr_t)frame_r[0xb8/8],
                                    (void*)frame_r,
                                    frame_r[0xb0/8] ? "" : "  <== callret_sp is ZERO (#42 trigger)");
                            }
                        }
                    }
                }
                /* iOS-Mythic ml329 (#53 discriminator): on a NULL-ish deref -- the exact
                 * shape of the IntrusivePooledAllocator crash (a list node read at
                 * offset 8 of a NULL `next`) -- state whether iOS zero-filled any page of
                 * FEX's host heap this run. Prints the verdict either way, so a run with
                 * no FEX-band recovery is a real negative that REFUTES #53 for this crash
                 * rather than silence. */
                if (siginfo->si_addr && (uintptr_t)siginfo->si_addr < 0x1000)
                {
                    extern void ios_reclaim_pages_report( const char *when, unsigned long long fault_addr );
                    ios_reclaim_pages_report( "fatal-segv", (unsigned long long)(uintptr_t)siginfo->si_addr );
                }
                ERR("  insn_stream PC-12..PC+8: %08x %08x %08x [%08x] %08x %08x %08x\n",
                    p[-3], p[-2], p[-1], p[0], p[1], p[2], p[3]);
            }
            else
                ERR("  insn=<unmappable PC, skipping read>\n");
            /* For tiny PC SEGVs through arm64x_check_call: probe LR-4 to
             * find the BLR that set up x11, and dump EC bitmap bit for x11
             * so we can see whether the bitmap fast-path should have taken
             * us out of arm64x_check_call. */
            if ((uintptr_t)PC_sig(context) < 0x100000000ULL)
            {
                extern PEB *peb;
                uintptr_t lr_val = (uintptr_t)REGn_sig(30, context);
                uintptr_t x11_at_seg = (uintptr_t)REGn_sig(11, context);
                ERR("  x11=%p lr=%p\n", (void*)x11_at_seg, (void*)lr_val);
                /* Decode the branch instruction at lr-4 to identify which
                 * register held the BR target at the time of the branch. */
                if (lr_val >= 0x100000004ULL)
                {
                    uint32_t branch_insn = *(uint32_t*)(lr_val - 4);
                    ERR("  branch@(lr-4)=%08x", branch_insn);
                    /* BR/BLR encoding: D61F0xxx (BR) or D63F0xxx (BLR) where
                     * bits 9:5 = Rn. */
                    if ((branch_insn & 0xFFFE0FFF) == 0xD61F0000) {
                        int rn = (branch_insn >> 5) & 0x1f;
                        ERR("    → BR x%d", rn);
                    } else if ((branch_insn & 0xFFFE0FFF) == 0xD63F0000) {
                        int rn = (branch_insn >> 5) & 0x1f;
                        ERR("    → BLR x%d", rn);
                    }
                    ERR("\n");
                    /* Dump 4 insns before the BLR — usually ADRP/ADRPL+LDR
                     * loading x16 from a dispatcher slot. Decode the slot
                     * address and the pointer it currently contains. */
                    if (lr_val >= 0x100000010ULL)
                    {
                        uint32_t i0 = *(uint32_t*)(lr_val - 16);
                        uint32_t i1 = *(uint32_t*)(lr_val - 12);
                        uint32_t i2 = *(uint32_t*)(lr_val - 8);
                        ERR("  call_site@(lr-16): %08x %08x %08x %08x\n",
                            i0, i1, i2, branch_insn);
                        /* Scan i0..i2 for an ADRP and following LDR loading
                         * x16, the BLR target. */
                        uint32_t insns[4] = { i0, i1, i2, branch_insn };
                        uintptr_t insn_pcs[4] = {
                            lr_val - 16, lr_val - 12, lr_val - 8, lr_val - 4 };
                        for (int k = 0; k < 3; k++)
                        {
                            uint32_t adrp = insns[k];
                            /* ADRP encoding: 1 | immlo[2] | 10000 | immhi[19] | Rd[5] */
                            if ((adrp & 0x9f000000) != 0x90000000) continue;
                            int rd = adrp & 0x1f;
                            int64_t immhi = (int64_t)((adrp >> 5) & 0x7ffff);
                            int64_t immlo = (int64_t)((adrp >> 29) & 3);
                            int64_t imm21 = (immhi << 2) | immlo;
                            if (imm21 & (1LL << 20)) imm21 |= (int64_t)0xffffffffffe00000;
                            uintptr_t adrp_pc = insn_pcs[k] & ~0xfffULL;
                            uintptr_t adrp_target = adrp_pc + (imm21 << 12);
                            ERR("    ADRP x%d → page %p (insn[%d]=%08x)\n",
                                rd, (void*)adrp_target, k, adrp);
                            /* Look for matching LDR in following insns. */
                            for (int m = k + 1; m < 4; m++)
                            {
                                uint32_t ldr = insns[m];
                                if ((ldr & 0xffc00000) != 0xf9400000) continue;
                                int rn_ldr = (ldr >> 5) & 0x1f;
                                int rt_ldr = ldr & 0x1f;
                                if (rn_ldr != rd) continue;
                                uint32_t imm12 = (ldr >> 10) & 0xfff;
                                uintptr_t slot_addr = adrp_target + (imm12 * 8);
                                ERR("    LDR x%d, [x%d, #0x%x] → slot=%p\n",
                                    rt_ldr, rn_ldr, imm12 * 8, (void*)slot_addr);
                                if (slot_addr >= 0x100000000ULL)
                                {
                                    void *slot_val = *(void**)slot_addr;
                                    extern uintptr_t ios_jit_reverse_translate_addr(void *addr);
                                    uintptr_t parent_slot = ios_jit_reverse_translate_addr((void*)slot_addr);
                                    void *parent_val = (parent_slot && parent_slot != slot_addr)
                                        ? *(void**)parent_slot : NULL;
                                    ERR("    JIT *slot = %p   parent@%p *slot = %p (expected %p)\n",
                                        slot_val, (void*)parent_slot, parent_val,
                                        peb ? peb->WerRegistrationData : NULL);
                                }
                                break;
                            }
                            break;
                        }
                    }
                }
                if (peb && peb->EcCodeBitMap && x11_at_seg >= 0x100000000ULL)
                {
                    uint64_t *bm = (uint64_t *)peb->EcCodeBitMap;
                    size_t page = x11_at_seg >> 12;
                    size_t blk  = page / 64;
                    int bit_in_blk = page & 63;
                    uint64_t blk_val = bm[blk];
                    int bit_set = (blk_val >> bit_in_blk) & 1;
                    ERR("  EcBitMap@%p: x11_page=0x%lx blk[%lx]=%llx bit=%d %s\n",
                        bm, (unsigned long)page, (unsigned long)blk,
                        (unsigned long long)blk_val, bit_set,
                        bit_set ? "(EC: fast-path SHOULD have taken)" : "(NOT EC: dispatch path taken)");
                }
                /* Dump the first 12 bytes at x11 (the called function's prologue)
                 * and at JIT-pool ntdll's __wine_dbg_header offset 0x5ed5c (the
                 * `ldr x11, [x18, #0x60]` instruction) to see whether our x18
                 * patcher replaced it with a B to a trampoline. */
                if (x11_at_seg >= 0x100000000ULL)
                {
                    uint32_t *p = (uint32_t *)x11_at_seg;
                    ERR("  callee prologue: %08x %08x %08x %08x\n",
                        p[0], p[1], p[2], p[3]);
                    /* If x11 is in __wine_dbg_header (0x5ed24), the LDR at
                     * +0x38 = +0xe (instr 14) is the patched one. Show it. */
                    uint32_t patched = p[14];
                    ERR("  callee[+0x38]=%08x (LDR x11,[x18,#0x60] should be B-tramp if patched)\n",
                        patched);
                    /* If patched is a B (top 6 bits = 0x05 = 0b000101), decode
                     * the target and dump trampoline bytes there. */
                    if ((patched >> 26) == 5)
                    {
                        int32_t imm26 = (int32_t)(patched & 0x3FFFFFF);
                        if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000; /* sign-ext */
                        intptr_t b_target = (intptr_t)(&p[14]) + ((intptr_t)imm26 << 2);
                        if (b_target >= 0x100000000LL)
                        {
                            uint32_t *t = (uint32_t *)b_target;
                            ERR("  tramp@%p: %08x %08x %08x %08x %08x %08x %08x\n",
                                (void*)b_target, t[0], t[1], t[2], t[3], t[4], t[5], t[6]);
                        }
                        else
                        {
                            ERR("  tramp_target=%p (out of range, B-encoding bad)\n",
                                (void*)b_target);
                        }
                    }
                    /* Search the whole prologue for any instructions where bits
                     * encode 0x39cc-style tiny RVA — could the prologue itself
                     * contain a corrupted instruction whose immediate field is
                     * the target we ended up at? */
                    {
                        uintptr_t bad_pc = (uintptr_t)PC_sig(context);
                        for (int s = 0; s < 32; s++)
                        {
                            if ((p[s] & 0xfffff) == (bad_pc & 0xfffff))
                            {
                                ERR("  callee[+0x%02x]=%08x has imm matching bad PC low20\n",
                                    s*4, p[s]);
                                break;
                            }
                        }
                    }
                }
                /* Dump arm64x_check_call's first 8 instructions in JIT pool. We
                 * are crashing INSIDE that function (BLR x16 at lr-4). Its first
                 * instruction is `ldr x16, [x18, #0x60]` — the ONE x18-using
                 * insn in its body. The x18 patcher should have replaced it with
                 * a B to a trampoline. If the B's target decodes outside the JIT
                 * pool's trampoline area, that's the bug.
                 * Address is stashed in peb->WerRegistrationData by Wine's
                 * arm64ec_process_init. */
                {
                    uint32_t *cc = peb ? (uint32_t *)peb->WerRegistrationData : NULL;
                    if ((uintptr_t)cc >= 0x100000000ULL)
                    {
                        ERR("  arm64x_check_call@%p: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                            cc, cc[0], cc[1], cc[2], cc[3], cc[4], cc[5], cc[6], cc[7]);
                        /* If cc[0] is a B (top 6 bits = 0x05 = 0b000101), decode
                         * its target and dump the trampoline contents there. */
                        if ((cc[0] >> 26) == 5)
                        {
                            int32_t imm26 = (int32_t)(cc[0] & 0x3FFFFFF);
                            if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000;
                            intptr_t b_target = (intptr_t)cc + ((intptr_t)imm26 << 2);
                            ERR("    cc[0] is B → target=%p (delta=%d insns)\n",
                                (void*)b_target, (int)imm26);
                            if (b_target >= 0x100000000LL)
                            {
                                uint32_t *t = (uint32_t *)b_target;
                                ERR("    cc-tramp@%p: %08x %08x %08x %08x %08x %08x %08x\n",
                                    (void*)b_target, t[0], t[1], t[2], t[3], t[4], t[5], t[6]);
                            }
                            else
                            {
                                ERR("    cc-tramp out of range — B encoding bad\n");
                            }
                        }
                        else
                        {
                            ERR("    cc[0] is NOT a B (opcode top6=%d) — patcher missed it\n",
                                (cc[0] >> 26));
                        }
                    }
                    else
                    {
                        ERR("  __os_arm64x_check_call=%p (not set or bad)\n", cc);
                    }
                }
            }
            /* Dump cpu_area (TEB.ChpeV2CpuAreaInfo) when PC is unmappable.
             * x17 typically holds cpu_area after enter_jit's chained loads,
             * so when we hit a tiny PC right after BR x16, x17 should still
             * have it. Bound-check x17 looks like a ~0x1xxxxxxxx pointer. */
            if ((uintptr_t)PC_sig(context) < 0x100000000ULL)
            {
                uintptr_t cpu_area_p = (uintptr_t)REGn_sig(17, context);
                if (cpu_area_p >= 0x100000000ULL && cpu_area_p < 0x800000000000ULL)
                {
                    uint64_t *ca = (uint64_t *)cpu_area_p;
                    ERR("  cpu_area@%p: [0x00]=%llx [0x08]=%llx [0x10]=%llx [0x18]=%llx\n",
                        (void*)cpu_area_p,
                        (unsigned long long)ca[0], (unsigned long long)ca[1],
                        (unsigned long long)ca[2], (unsigned long long)ca[3]);
                    ERR("              [0x20]=%llx [0x28]=%llx [0x30]=%llx [0x38]=%llx\n",
                        (unsigned long long)ca[4], (unsigned long long)ca[5],
                        (unsigned long long)ca[6], (unsigned long long)ca[7]);
                    ERR("              [0x40]=%llx [0x48]=%llx [0x50]=%llx [0x58]=%llx\n",
                        (unsigned long long)ca[8], (unsigned long long)ca[9],
                        (unsigned long long)ca[10], (unsigned long long)ca[11]);
                }
            }
        }
    }
#endif
    rec.NumberParameters = 2;
    if ((esr & 0xf0000000) == 0x80000000) rec.ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
    else if (esr & 0x40) rec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
    else rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
    rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
#ifdef WINE_IOS
    {
        static uintptr_t last_fault_pc = 0;
        static int fault_repeat_count = 0;
        uintptr_t this_pc = PC_sig(context);
        if (this_pc == last_fault_pc)
        {
            fault_repeat_count++;
            static unsigned long loop_storm;
            if (fault_repeat_count == 3 && ios_sig_storm_gate( &loop_storm ))
            {
                ERR("SEGV LOOP DETECTED: pc=%p addr=%p repeated %d times, dumping TEB+PEB\n",
                    (void*)this_pc, siginfo->si_addr, fault_repeat_count);
                /* Dump TEB */
                if (ios_teb_for_signals)
                {
                    uint64_t *teb = (uint64_t *)ios_teb_for_signals;
                    ERR("  TEB[0x00]=%p TEB[0x08]=%p TEB[0x10]=%p TEB[0x18]=%p\n",
                        (void*)teb[0], (void*)teb[1], (void*)teb[2], (void*)teb[3]);
                    ERR("  TEB[0x20]=%p TEB[0x28]=%p TEB[0x30]=%p TEB[0x38]=%p\n",
                        (void*)teb[4], (void*)teb[5], (void*)teb[6], (void*)teb[7]);
                    ERR("  TEB[0x40]=%p TEB[0x48]=%p TEB[0x50]=%p TEB[0x58]=%p\n",
                        (void*)teb[8], (void*)teb[9], (void*)teb[10], (void*)teb[11]);
                    ERR("  TEB[0x60]=%p TEB[0x68]=%p TEB[0x70]=%p TEB[0x78]=%p\n",
                        (void*)teb[12], (void*)teb[13], (void*)teb[14], (void*)teb[15]);
                    /* Dump PEB (TEB+0x60 is PEB pointer) */
                    uint64_t peb_addr = teb[12]; /* TEB[0x60] */
                    if (peb_addr > 0x10000)
                    {
                        uint64_t *peb = (uint64_t *)peb_addr;
                        ERR("  PEB @ %p:\n", (void*)peb_addr);
                        ERR("  PEB[0x00]=%p PEB[0x08]=%p PEB[0x10]=%p PEB[0x18]=%p\n",
                            (void*)peb[0], (void*)peb[1], (void*)peb[2], (void*)peb[3]);
                        ERR("  PEB[0x20]=%p PEB[0x28]=%p PEB[0x30]=%p PEB[0x38]=%p\n",
                            (void*)peb[4], (void*)peb[5], (void*)peb[6], (void*)peb[7]);
                        ERR("  PEB[0x40]=%p PEB[0x48]=%p PEB[0x50]=%p PEB[0x58]=%p\n",
                            (void*)peb[8], (void*)peb[9], (void*)peb[10], (void*)peb[11]);
                        ERR("  PEB[0x60]=%p PEB[0x68]=%p PEB[0x70]=%p PEB[0x78]=%p\n",
                            (void*)peb[12], (void*)peb[13], (void*)peb[14], (void*)peb[15]);
                        /* Dump PEB->Ldr (PEB+0x18) if it looks valid */
                        uint64_t ldr_addr = peb[3]; /* PEB[0x18] */
                        ERR("  PEB->Ldr = %p\n", (void*)ldr_addr);
                        if (ldr_addr > 0x10000)
                        {
                            uint64_t *ldr = (uint64_t *)ldr_addr;
                            ERR("  LDR[0x00]=%p LDR[0x08]=%p LDR[0x10]=%p LDR[0x18]=%p\n",
                                (void*)ldr[0], (void*)ldr[1], (void*)ldr[2], (void*)ldr[3]);
                            ERR("  LDR[0x20]=%p LDR[0x28]=%p LDR[0x30]=%p LDR[0x38]=%p\n",
                                (void*)ldr[4], (void*)ldr[5], (void*)ldr[6], (void*)ldr[7]);
                        }
                        else
                        {
                            ERR("  PEB->Ldr is INVALID (0x%lx)!\n", (unsigned long)ldr_addr);
                        }
                    }
                }
            }
            if (fault_repeat_count >= 5)
            {
                ERR("SEGV LOOP FATAL: pc=%p addr=%p after %d repeats, forcing thread exit\n",
                    (void*)this_pc, siginfo->si_addr, fault_repeat_count);
                /* Skip the faulting instruction and set return value to indicate failure */
                PC_sig(context) = PC_sig(context) + 4;
                REGn_sig(0, context) = 0xDEAD0001;
                ios_fixup_x18_for_return( context );
                last_fault_pc = 0;
                fault_repeat_count = 0;
                return;
            }
        }
        else
        {
            last_fault_pc = this_pc;
            fault_repeat_count = 1;
        }
    }
#endif
    if (!virtual_handle_fault( &rec, (void *)SP_sig(context) ))
    {
#ifdef WINE_IOS
        ERR("virtual_handle_fault HANDLED addr=%p\n", siginfo->si_addr);
        ios_fixup_x18_for_return( context );
#endif
        return;
    }
    if (handle_syscall_fault( context, &rec ))
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( context );
#endif
        return;
    }
#ifdef WINE_IOS
    ERR("setup_exception for SEGV at pc=%p addr=%p (virtual_handle_fault failed)\n",
        (void*)PC_sig(context), siginfo->si_addr);
    /* Steam S3 (task #29): name the native faulting code + the target
     * memory region so the unhandled-write fault is diagnosable. */
    {
        extern void ios_dump_fault_region( void *addr );
        Dl_info di;
        uint64_t pcv = (uint64_t)PC_sig(context);
        if (dladdr( (void *)(uintptr_t)pcv, &di ) && di.dli_fname)
            dprintf( 2, "[fault-pc] pc=%p = %s`%s+0x%llx (img base %p, slide-relative)\n",
                     (void *)(uintptr_t)pcv, di.dli_fname,
                     di.dli_sname ? di.dli_sname : "?",
                     (unsigned long long)(pcv - (uint64_t)(uintptr_t)(di.dli_saddr ? di.dli_saddr : di.dli_fbase)),
                     di.dli_fbase );
        ios_dump_fault_region( siginfo->si_addr );
    }
#endif
    setup_exception( context, &rec );
}


/**********************************************************************
 *		ill_handler
 *
 * Handler for SIGILL.
 */
static void ill_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_ILLEGAL_INSTRUCTION };
    ucontext_t *context = sigcontext;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
    ERR("ILL at pc=%p\n", (void*)PC_sig(context));
    {
        /* iOS-Mythic diagnostic: when we ILL on a zero/empty page, dump full
         * register state + walk back FP chain to find who BR'd here. */
        uint64_t pc  = (uint64_t)PC_sig(context);
        uint64_t lr  = (uint64_t)REGn_sig(30, context);
        uint64_t fp  = (uint64_t)REGn_sig(29, context);
        uint64_t sp  = (uint64_t)arm_thread_state64_get_sp(context->uc_mcontext->__ss);
        uint64_t x0  = (uint64_t)REGn_sig(0,  context);
        uint64_t x9  = (uint64_t)REGn_sig(9,  context);
        uint64_t x16 = (uint64_t)REGn_sig(16, context);
        uint64_t x17 = (uint64_t)REGn_sig(17, context);
        uint64_t x18 = (uint64_t)REGn_sig(18, context);
        uint64_t x19 = (uint64_t)REGn_sig(19, context);
        ERR("ILL diag: pc=0x%llx lr=0x%llx fp=0x%llx sp=0x%llx\n",
            (unsigned long long)pc, (unsigned long long)lr,
            (unsigned long long)fp, (unsigned long long)sp);
        ERR("ILL diag: x0=0x%llx x9=0x%llx x16=0x%llx x17=0x%llx x18=0x%llx x19=0x%llx\n",
            (unsigned long long)x0, (unsigned long long)x9,
            (unsigned long long)x16, (unsigned long long)x17,
            (unsigned long long)x18, (unsigned long long)x19);
        /* Decode caller_insn at LR-4 (the BL/BLR that brought us here) */
        if (lr >= 0x100000000ULL && lr < 0x800000000ULL) {
            vm_size_t outsz = 4;
            uint32_t caller_insn = 0;
            if (vm_read_overwrite(mach_task_self(), lr - 4, 4,
                                  (vm_address_t)&caller_insn, &outsz) == KERN_SUCCESS)
                ERR("ILL diag: caller_insn @lr-4 = 0x%08x\n", caller_insn);
        }
        /* Walk back FP chain (each frame: fp[0]=prev_fp, fp[1]=saved_lr) */
        for (int frame = 0; frame < 8 && fp >= 0x100000000ULL && fp < 0x800000000ULL; frame++) {
            vm_size_t outsz = 8;
            uint64_t prev_fp = 0, saved_lr = 0;
            if (vm_read_overwrite(mach_task_self(), fp,     8, (vm_address_t)&prev_fp,  &outsz) != KERN_SUCCESS) break;
            outsz = 8;
            if (vm_read_overwrite(mach_task_self(), fp + 8, 8, (vm_address_t)&saved_lr, &outsz) != KERN_SUCCESS) break;
            ERR("ILL diag: frame[%d] fp=0x%llx saved_lr=0x%llx\n",
                frame, (unsigned long long)fp, (unsigned long long)saved_lr);
            if (prev_fp <= fp) break;
            fp = prev_fp;
        }
        /* iOS-Mythic 2026-07-06 (Thumper desktop ILL): both crashes were the
         * FEX dispatcher's ExitFunctionLinker thunk doing `ldr x2,[x28,#0x630];
         * blr x2` with a corrupted Pointers.ExitFunctionLink (pointed into a
         * mid-emission block tail instead of the C++ resolver). Dump the
         * evidence at crash time: x28 (STATE), x1 (link Record ptr), x2 (the
         * loaded target), the CpuStateFrame Pointers region around +0x630,
         * and the Record bytes — distinguishes single-field corruption vs
         * wild-store span vs corrupt Record. */
        {
            uint64_t x1  = (uint64_t)REGn_sig(1,  context);
            uint64_t x2  = (uint64_t)REGn_sig(2,  context);
            uint64_t x28 = (uint64_t)REGn_sig(28, context);
            uint64_t x6  = (uint64_t)REGn_sig(6,  context);
            uint64_t x10 = (uint64_t)REGn_sig(10, context);
            uint64_t x11 = (uint64_t)REGn_sig(11, context);
            ERR("ILL diag: x1=0x%llx x2=0x%llx x28=0x%llx\n",
                (unsigned long long)x1, (unsigned long long)x2, (unsigned long long)x28);
            /* x6 = guest RIP and x11 = branch target in FEX's inline exit
             * dispatch (`ret x11`); x10 = dispatcher's CompileBlock-return
             * target (`br x10`). Whichever equals pc names the faulting
             * branch. */
            ERR("ILL diag: x6=0x%llx x10=0x%llx x11=0x%llx (pc==x11? %d pc==x10? %d)\n",
                (unsigned long long)x6, (unsigned long long)x10, (unsigned long long)x11,
                x11 == pc, x10 == pc);
            /* FEX inline L1 exit-dispatch reads {L1Ptr, L1Mask} at STATE+0xa0
             * and the entry pair {host, guest} at L1Ptr + (rip & mask)<<?.
             * Dump the entry for x6 so a torn pair is visible at crash time.
             * Windows-heap frames live at 0x70xxxxxxxx — include them. */
            if (x28 >= 0x100000000ULL && x28 < 0x8000000000ULL)
            {
                uint64_t l1pair[2] = {0, 0}, entry[2] = {0, 0};
                vm_size_t osz = sizeof(l1pair);
                if (vm_read_overwrite(mach_task_self(), x28 + 0xa0, sizeof(l1pair),
                                      (vm_address_t)l1pair, &osz) == KERN_SUCCESS)
                {
                    /* mask is pre-shifted per dispatcher code: and x11, mask, rip<<4 */
                    uint64_t eaddr = l1pair[0] + ((x6 << 4) & l1pair[1]);
                    ERR("ILL diag: L1ptr=0x%llx L1mask=0x%llx entry@0x%llx\n",
                        (unsigned long long)l1pair[0], (unsigned long long)l1pair[1],
                        (unsigned long long)eaddr);
                    osz = sizeof(entry);
                    if (l1pair[0] &&
                        vm_read_overwrite(mach_task_self(), eaddr, sizeof(entry),
                                          (vm_address_t)entry, &osz) == KERN_SUCCESS)
                        ERR("ILL diag: L1 entry: host=0x%llx guest=0x%llx (guest==x6? %d host==pc? %d)\n",
                            (unsigned long long)entry[0], (unsigned long long)entry[1],
                            entry[1] == x6, entry[0] == pc);
                }
            }
            if (x28 >= 0x100000000ULL && x28 < 0x800000000ULL)
            {
                uint64_t words[32];
                vm_size_t outsz = sizeof(words);
                if (vm_read_overwrite(mach_task_self(), x28 + 0x5c0, sizeof(words),
                                      (vm_address_t)words, &outsz) == KERN_SUCCESS)
                {
                    for (int w = 0; w < 32; w += 4)
                        ERR("ILL diag: STATE+0x%03x: %016llx %016llx %016llx %016llx\n",
                            0x5c0 + w * 8,
                            (unsigned long long)words[w],   (unsigned long long)words[w+1],
                            (unsigned long long)words[w+2], (unsigned long long)words[w+3]);
                }
                /* State.rip lives in the first 0x100 of the frame */
                outsz = sizeof(words);
                if (vm_read_overwrite(mach_task_self(), x28, 0x40,
                                      (vm_address_t)words, &outsz) == KERN_SUCCESS)
                    ERR("ILL diag: STATE+0: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                        (unsigned long long)words[0], (unsigned long long)words[1],
                        (unsigned long long)words[2], (unsigned long long)words[3],
                        (unsigned long long)words[4], (unsigned long long)words[5],
                        (unsigned long long)words[6], (unsigned long long)words[7]);
            }
            if (x1 >= 0x100000000ULL && x1 < 0x800000000ULL)
            {
                uint64_t rec[6];
                vm_size_t outsz = sizeof(rec);
                if (vm_read_overwrite(mach_task_self(), x1, sizeof(rec),
                                      (vm_address_t)rec, &outsz) == KERN_SUCCESS)
                    ERR("ILL diag: Record@x1: %016llx %016llx %016llx %016llx %016llx %016llx\n",
                        (unsigned long long)rec[0], (unsigned long long)rec[1],
                        (unsigned long long)rec[2], (unsigned long long)rec[3],
                        (unsigned long long)rec[4], (unsigned long long)rec[5]);
            }
        }
        /* iOS-Mythic: also dump JIT pool here (the Mach UNHANDLED path may not
         * fire for ILL since we deliver via setup_exception). One-shot. */
        {
            static volatile int ill_dumped = 0;
            if (__sync_bool_compare_and_swap(&ill_dumped, 0, 1)) {
                extern void *ios_jit_rw_base_global;
                extern size_t ios_jit_pool_size_global;
                if (ios_jit_rw_base_global && ios_jit_pool_size_global) {
                    const char *docs = getenv("MYTHIC_DOCS_DIR");
                    char path[512];
                    if (docs) snprintf(path, sizeof(path), "%s/fex-jit-dump.bin", docs);
                    else      snprintf(path, sizeof(path), "/tmp/fex-jit-dump.bin");
                    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd >= 0) {
                        ssize_t off = 0;
                        size_t total = ios_jit_pool_size_global;
                        while ((size_t)off < total) {
                            ssize_t n = write(fd, (char*)ios_jit_rw_base_global + off,
                                              total - off > 0x10000 ? 0x10000 : total - off);
                            if (n <= 0) break;
                            off += n;
                        }
                        close(fd);
                        ERR("ILL diag: DUMPED JIT pool RW alias (%zd bytes) to %s\n", off, path);
                    }
                }
            }
        }
    }
#endif

    if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
        !(PC_sig( context ) & 3))
    {
        ULONG instr = *(ULONG *)PC_sig( context );
        /* emulate mrs xN, CurrentEL */
        if ((instr & ~0x1f) == 0xd5384240) {
            ULONG reg = instr & 0x1f;
            /* ignore writes to xzr */
            if (reg != 31) REGn_sig(reg, context) = 0;
            PC_sig(context) += 4;
#ifdef WINE_IOS
            ios_fixup_x18_for_return( context );
#endif
            return;
        }
    }

    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		ios_emulate_store
 *
 * Emulate an ARM64 store instruction, writing through the JIT pool's
 * RW view instead of the RX view. Returns 1 on success, 0 if the
 * instruction isn't a recognized store.
 */
#ifdef WINE_IOS
static inline uint64_t ios_get_reg(ucontext_t *ctx, int r)
{
    if (r == 31) return 0;  /* XZR */
    /* REGn_sig(0..30) works because __x[29]=__fp, __x[30]=__lr in memory layout */
    return REGn_sig(r, ctx);
}

static int ios_emulate_store(ucontext_t *ctx, uint32_t insn, uintptr_t rw_addr)
{
    int rt = insn & 0x1F;
    uint64_t rt_val = ios_get_reg(ctx, rt);

    /* STR/STRB/STRH (unsigned offset):
     * size[31:30] 111 0 01 00 imm12 Rn Rt
     * Matching bits [29:22] = 11100100 */
    if ((insn & 0x3FC00000) == 0x39000000)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    /* STUR / STR pre-index / STR post-index (9-bit immediate):
     * size[31:30] 111 0 00 00 0 imm9 type Rn Rt
     * Matching bits [29:21] = 111000000 */
    if ((insn & 0x3FE00000) == 0x38000000)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    /* STP (signed offset / pre-index / post-index):
     * opc[31:30] 101 0 0xx 0 imm7 Rt2 Rn Rt
     * Matching bits [29:25,22] = 10100_0, various x bits for variant */
    if ((insn & 0x3E400000) == 0x28000000)
    {
        int opc = (insn >> 30) & 3;
        int rt2 = (insn >> 10) & 0x1F;
        uint64_t rt2_val = ios_get_reg(ctx, rt2);

        if (opc & 2) {  /* 64-bit */
            *(uint64_t *)rw_addr = rt_val;
            *(uint64_t *)(rw_addr + 8) = rt2_val;
        } else {  /* 32-bit */
            *(uint32_t *)rw_addr = (uint32_t)rt_val;
            *(uint32_t *)(rw_addr + 4) = (uint32_t)rt2_val;
        }
        return 1;
    }

    /* STR (register offset):
     * size[31:30] 111 0 00 01 Rm option S 10 Rn Rt */
    if ((insn & 0x3FE00C00) == 0x38200800)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    return 0;  /* unhandled instruction */
}
#endif


/**********************************************************************
 *		bus_handler
 *
 * Handler for SIGBUS.
 */
static void bus_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_DATATYPE_MISALIGNMENT };
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
    static int bus_count = 0;
    bus_count++;
    if (bus_count <= 5)
    {
        uintptr_t bus_pc_val = (uintptr_t)PC_sig((ucontext_t*)sigcontext);
        uintptr_t bus_lr_val = (uintptr_t)LR_sig((ucontext_t*)sigcontext);
        /* iOS user space starts ~0x100000000; anything below is unmapped. */
        int bus_pc_ok = (bus_pc_val >= 0x100000000ULL);
        int bus_lr_ok = (bus_lr_val >= 0x100000000ULL + 4);
        uint32_t bus_insn = bus_pc_ok ? *(uint32_t*)bus_pc_val : 0;
        uint32_t bus_branch_insn = bus_lr_ok ? *(uint32_t*)(bus_lr_val - 4) : 0;
        ERR("BUS #%d: pc=%p addr=%p x16=%p x17=%p x18=%p lr=%p insn=0x%08x branch@lr-4=0x%08x%s\n",
            bus_count, (void*)bus_pc_val, siginfo->si_addr,
            (void*)REGn_sig(16, (ucontext_t*)sigcontext),
            (void*)REGn_sig(17, (ucontext_t*)sigcontext),
            (void*)REGn_sig(18, (ucontext_t*)sigcontext),
            (void*)bus_lr_val, bus_insn, bus_branch_insn,
            bus_pc_ok ? "" : " <unmappable PC>");
        /* Dump Mach handler .data fault diagnostic (first fault only) */
        if (bus_count == 1 && ios_exc_data_fault_count > 0)
        {
            ERR("  Mach 1st .data: pc=0x%llx lr=0x%llx sp=0x%llx cnt=%d\n",
                (unsigned long long)ios_exc_data_fault_pc,
                (unsigned long long)ios_exc_data_fault_lr,
                (unsigned long long)ios_exc_data_fault_sp,
                ios_exc_data_fault_count);
            ERR("  Mach regs: x0=%llx x1=%llx x2=%llx x3=%llx\n",
                (unsigned long long)ios_exc_data_x0,
                (unsigned long long)ios_exc_data_x1,
                (unsigned long long)ios_exc_data_x2,
                (unsigned long long)ios_exc_data_x3);
            ERR("  Mach regs: x16=%llx x17=%llx x18=%llx x29=%llx\n",
                (unsigned long long)ios_exc_data_x16,
                (unsigned long long)ios_exc_data_x17,
                (unsigned long long)ios_exc_data_x18,
                (unsigned long long)ios_exc_data_x29);
            ERR("  insn@LR=0x%08x frame_ptr=0x%llx frame->pc=0x%llx\n",
                ios_exc_data_insn_at_lr,
                (unsigned long long)ios_exc_data_fault_frame_ptr,
                (unsigned long long)ios_exc_data_fault_frame_pc);
        }
    }
    ucontext_t *bus_ctx = sigcontext;
    void *pc = (void *)PC_sig(bus_ctx);
    int is_exec_fault = (pc == siginfo->si_addr);

    /* 1. Execution fault (pc == fault_addr): redirect to JIT pool copy.
     * This handles indirect calls through function pointers, import tables, etc. */
    if (is_exec_fault)
    {
        extern void *ios_jit_translate_addr(void *addr);
        extern int ios_jit_addr_is_text(uintptr_t addr);
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        extern uintptr_t ios_jit_anon_alias_lookup_rx(uintptr_t fault_addr);

        void *jit_pc = ios_jit_translate_addr(pc);
        if (jit_pc == pc) {
            /* Try the anon-alias table (FEX CodeBuffer / runtime JIT) */
            uintptr_t rx_pc = ios_jit_anon_alias_lookup_rx((uintptr_t)pc);
            if (rx_pc) jit_pc = (void *)rx_pc;
        }
        if (jit_pc != pc)
        {
            /* Use trampoline to set x18 (sigreturn zeroes it on iOS) */
            if (ios_my_trampoline && ios_teb_for_signals)
            {
                REGn_sig(17, bus_ctx) = (uintptr_t)jit_pc;
                PC_sig(bus_ctx) = (uintptr_t)ios_my_trampoline;
            }
            else
            {
                PC_sig(bus_ctx) = (uintptr_t)jit_pc;
            }
            return;  /* Resume from JIT pool address */
        }

        /* Execution fault at address already in JIT pool (can't redirect).
         * This means code jumped into a non-executable section (.data, .rdata).
         * Do NOT fall through to store emulation — that would walk PC through
         * data bytes for thousands of faults. Log diagnostics and crash. */
        {
            uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
            size_t pool_sz = ios_jit_pool_size_global;
            if (rx && (uintptr_t)pc >= rx && (uintptr_t)pc < rx + pool_sz)
            {
                extern volatile uint64_t g_wine_return_pc;
                extern volatile uint64_t g_wine_return_x18;
                extern volatile uint64_t g_wine_return_count;
                ERR("BUS EXEC in JIT .data: pc=%p (pool+0x%lx) lr=%p sp=%p\n",
                    pc, (unsigned long)((uintptr_t)pc - rx),
                    (void*)LR_sig(bus_ctx), (void*)SP_sig(bus_ctx));
                ERR("  x0=%p x1=%p x2=%p x3=%p\n",
                    (void*)REGn_sig(0, bus_ctx), (void*)REGn_sig(1, bus_ctx),
                    (void*)REGn_sig(2, bus_ctx), (void*)REGn_sig(3, bus_ctx));
                ERR("  x16=%p x17=%p x18=%p x29=%p\n",
                    (void*)REGn_sig(16, bus_ctx), (void*)REGn_sig(17, bus_ctx),
                    (void*)REGn_sig(18, bus_ctx), (void*)REGn_sig(29, bus_ctx));
                ERR("  last dispatcher_return: pc=%p x18=%p count=%llu\n",
                    (void*)(uintptr_t)g_wine_return_pc,
                    (void*)(uintptr_t)g_wine_return_x18,
                    (unsigned long long)g_wine_return_count);
                {
                    extern volatile uint64_t g_wine_dispatcher_count;
                    extern volatile int ios_total_segv_count;
                    /* Read instruction at LR-4 (the BL/BLR that set LR) */
                    uint32_t insn_lr_m4 = 0;
                    uintptr_t lr_val = (uintptr_t)LR_sig(bus_ctx);
                    if (lr_val >= 4) insn_lr_m4 = *(uint32_t *)(lr_val - 4);
                    ERR("  disp_entry=%llu segv_count=%d insn@LR-4=0x%08x\n",
                        (unsigned long long)g_wine_dispatcher_count,
                        ios_total_segv_count, insn_lr_m4);
                }
                ERR("  is_text=%d mach_data_faults=%d mach_x18_fixes=%lld\n",
                    ios_jit_addr_is_text((uintptr_t)pc),
                    ios_exc_data_fault_count, (long long)ios_exc_x18_fixes);
                /* Dump ring buffer of last 8 dispatcher_return PCs */
                {
                    extern volatile uint64_t g_wine_return_ring[8];
                    extern volatile uint32_t g_wine_return_ring_idx;
                    uint32_t ri = g_wine_return_ring_idx;
                    ERR("  ret ring (newest→oldest): %p %p %p %p %p %p %p %p\n",
                        (void*)(uintptr_t)g_wine_return_ring[(ri-1)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-2)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-3)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-4)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-5)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-6)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-7)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-8)&7]);
                }
                /* Don't try store emulation, go straight to exception */
                goto bus_fatal;
            }
        }
    }

    /* 2. Data write fault (pc != fault_addr): code in JIT pool tries to write
     * to a data section in the JIT pool RX view. Emulate the store by
     * writing through the RW view instead. */
    {
        extern void *ios_jit_rx_base_global;
        extern void *ios_jit_rw_base_global;
        extern size_t ios_jit_pool_size_global;

        uintptr_t fault = (uintptr_t)siginfo->si_addr;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
        size_t pool_sz = ios_jit_pool_size_global;

        if (rx && fault >= rx && fault < rx + pool_sz)
        {
            uintptr_t rw_addr = fault - rx + rw;
            uint32_t insn = *(uint32_t *)(uintptr_t)PC_sig(bus_ctx);

            if (ios_emulate_store(bus_ctx, insn, rw_addr))
            {
                PC_sig(bus_ctx) += 4;
                ios_fixup_x18_for_return( bus_ctx );
                return;  /* Resume after the emulated store */
            }
            /* ml264 (#45): NAME THE MEMORY, not the instruction.
             *
             * All four failing instructions in ml264 target the SAME address
             * 0x156a097b0 (pool offset 0x361b57b0, tail/JIT-code area) and all four
             * are ATOMICS of different widths:
             *   0x88eafe89  CAS   32-bit   x1
             *   0xc8f1fd60  CAS   64-bit   x1
             *   0x4866fd64  CASPAL 128-bit x1
             *   0x4866fe6a  CASPAL 128-bit x59
             * A location that rejects atomics at EVERY width is not an instruction
             * problem -- the Size==1 CASPAL implementation is in and working, and
             * [caspal128] is silent. On Apple silicon LSE atomics require normal
             * cacheable memory, and this pool is mach_vm_remap dual-mapped (RW alias
             * + RX alias), which is exactly the kind of mapping where they fault.
             *
             * Two readings need opposite fixes: (a) the whole dual-mapped pool
             * rejects atomics -- then FEX's own atomics on pool-resident structures
             * can never work there and the data must move; (b) only THIS page is bad
             * (reclaimed, or the single-page RW poison of task #41) -- a page-level
             * problem with a page-level fix. protection/max_protection/share_mode/
             * user_tag distinguish them. Capped; fires only on an already-fatal path. */
            {
                static int busrgn;
                if (busrgn++ < 10)
                {
                    mach_vm_address_t ba = (mach_vm_address_t)(uintptr_t)siginfo->si_addr;
                    mach_vm_size_t bs = 0;
                    vm_region_basic_info_data_64_t bbi;
                    mach_msg_type_number_t bbc = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t bbo = MACH_PORT_NULL;
                    mach_vm_address_t xa = (mach_vm_address_t)(uintptr_t)siginfo->si_addr;
                    mach_vm_size_t xs = 0;
                    vm_region_extended_info_data_t xi;
                    mach_msg_type_number_t xc = VM_REGION_EXTENDED_INFO_COUNT;
                    mach_port_t xo = MACH_PORT_NULL;
                    extern void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uintptr_t rxb = (uintptr_t)ios_jit_rx_base_global;
                    uintptr_t rwb = (uintptr_t)ios_jit_rw_base_global;
                    size_t psz = ios_jit_pool_size_global;
                    uintptr_t fa = (uintptr_t)siginfo->si_addr;
                    const char *where = "outside pool";

                    if (rxb && fa >= rxb && fa < rxb + psz) where = "JIT-POOL-RX (dual-mapped)";
                    else if (rwb && fa >= rwb && fa < rwb + psz) where = "JIT-POOL-RW (alias)";

                    if (mach_vm_region( mach_task_self(), &ba, &bs, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&bbi, &bbc, &bbo ) == KERN_SUCCESS &&
                        mach_vm_region( mach_task_self(), &xa, &xs, VM_REGION_EXTENDED_INFO,
                                        (vm_region_info_t)&xi, &xc, &xo ) == KERN_SUCCESS)
                        ERR("[atomic-mem] addr=%p %s pooloff=0x%llx | region=0x%llx+0x%llx "
                            "prot=%d max=%d share_mode=%d user_tag=%d\n",
                            siginfo->si_addr, where,
                            (unsigned long long)(rxb && fa >= rxb ? fa - rxb : 0),
                            (unsigned long long)ba, (unsigned long long)bs,
                            bbi.protection, bbi.max_protection, xi.share_mode, xi.user_tag);
                    else
                        ERR("[atomic-mem] addr=%p %s -- mach_vm_region FAILED (unmapped?)\n",
                            siginfo->si_addr, where);
                }
            }
            ERR("BUS: unhandled store insn=0x%08x at pc=%p addr=%p\n",
                insn, pc, siginfo->si_addr);
        }
    }

bus_fatal:
    ERR("BUS at pc=%p addr=%p exec=%d\n", pc, siginfo->si_addr, is_exec_fault);
#endif
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		trap_handler
 *
 * Handler for SIGTRAP.
 */
static void trap_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    CONTEXT ctx;
#ifdef WINE_IOS
    /* StikDebug protocol BRK #0xf00d with no debugger left to catch it —
     * e.g. the detach BRK re-executing after StikDebug lets go, on a
     * TEB-less app thread. Check at ENTRY, before any si_code dispatch:
     * iOS delivers BRK-derived SIGTRAPs with varying si_code, and letting
     * this fall into the wine exception path wedges the thread inside
     * nested fault logging (2026-07-06). Skip the insn, x0=0 (failure). */
    if (!(PC_sig( context ) & 3) && *(ULONG *)PC_sig( context ) == 0xd43e01a0)
    {
        dprintf(2, "[brk-f00d] skipped stray StikDebug BRK at pc=%p (si_code=%d)\n",
                (void *)PC_sig( context ), siginfo->si_code);
        REGn_sig( 0, context ) = 0;
        PC_sig( context ) += 4;
        return;
    }
    ios_track_signal( signal, context );
#endif

    rec.ExceptionAddress = (void *)PC_sig(context);
    save_context( &ctx, sigcontext );

    switch (siginfo->si_code)
    {
    case TRAP_TRACE:
        rec.ExceptionCode = EXCEPTION_SINGLE_STEP;
        break;
    case TRAP_BRKPT:
        /* debug exceptions do not update ESR on Linux, so we fetch the instruction directly. */
        if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
            !(PC_sig( context ) & 3))
        {
            ULONG imm = (*(ULONG *)PC_sig( context ) >> 5) & 0xffff;
            switch (imm)
            {
            case 0xf00d:
                /* StikDebug JIT-protocol BRK (detach/prepare_region) with no
                 * debugger left to catch it — e.g. the detach BRK re-executes
                 * after StikDebug lets go, on a TEB-less app thread. This is
                 * an app-side handshake, never a guest exception: skip the
                 * insn, report failure in x0, and get out before any wine
                 * exception machinery (which wedged the detach thread inside
                 * dbg logging, 2026-07-06). */
                REGn_sig( 0, context ) = 0;
                PC_sig( context ) += 4;
                return;
            case 0xf000:
                ctx.Pc += 4;  /* skip the brk instruction */
                rec.ExceptionCode = EXCEPTION_BREAKPOINT;
                rec.NumberParameters = 1;
                break;
            case 0xf001:
                rec.ExceptionCode = STATUS_ASSERTION_FAILURE;
                break;
            case 0xf003:
                rec.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
                rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
                rec.NumberParameters = 1;
                rec.ExceptionInformation[0] = ctx.X[0];
                NtRaiseException( &rec, &ctx, FALSE );
                break;
            case 0xf004:
                rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
                break;
            default:
                rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
                break;
            }
        }
        break;
    default:
        rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    }

    setup_raise_exception( sigcontext, &rec, &ctx );
}

/**********************************************************************
 *		fpe_handler
 *
 * Handler for SIGFPE.
 */
static void fpe_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif

    switch (siginfo->si_code & 0xffff )
    {
#ifdef FPE_FLTSUB
    case FPE_FLTSUB:
        rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
#endif
#ifdef FPE_INTDIV
    case FPE_INTDIV:
        rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_INTOVF
    case FPE_INTOVF:
        rec.ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTDIV
    case FPE_FLTDIV:
        rec.ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_FLTOVF
    case FPE_FLTOVF:
        rec.ExceptionCode = EXCEPTION_FLT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTUND
    case FPE_FLTUND:
        rec.ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
        break;
#endif
#ifdef FPE_FLTRES
    case FPE_FLTRES:
        rec.ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
        break;
#endif
#ifdef FPE_FLTINV
    case FPE_FLTINV:
#endif
    default:
        rec.ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
        break;
    }
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		int_handler
 *
 * Handler for SIGINT.
 */
static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    HANDLE handle;
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif

    if (!p__wine_ctrl_routine)
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( sigcontext );
#endif
        return;
    }
    if (!NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                           p__wine_ctrl_routine, 0 /* CTRL_C_EVENT */, 0, 0, 0, 0, NULL ))
        NtClose( handle );
#ifdef WINE_IOS
    ios_fixup_x18_for_return( sigcontext );
#endif
}


/**********************************************************************
 *		abrt_handler
 *
 * Handler for SIGABRT.
 */
static void abrt_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_WINE_ASSERTION, EXCEPTION_NONCONTINUABLE };
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		quit_handler
 *
 * Handler for SIGQUIT.
 */
static void quit_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *context = sigcontext;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
#endif
    if (!is_inside_syscall( SP_sig(context) )) user_mode_abort_thread( 0, get_syscall_frame() );
    abort_thread(0);
}


/**********************************************************************
 *		usr1_handler
 *
 * Handler for SIGUSR1, used to signal a thread that it got suspended.
 */
static void usr1_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *ucontext = sigcontext;
    CONTEXT context;
#ifdef WINE_IOS
    ios_track_signal( signal, ucontext );
#endif
    if (is_inside_syscall( SP_sig(ucontext) ))
    {
        context.ContextFlags = CONTEXT_FULL | CONTEXT_EXCEPTION_REQUEST;
        NtGetContextThread( GetCurrentThread(), &context );
        wait_suspend( &context );
        NtSetContextThread( GetCurrentThread(), &context );
    }
    else
    {
        save_context( &context, ucontext );
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING;
        wait_suspend( &context );
        restore_context( &context, ucontext );
#ifdef WINE_IOS
        ios_fixup_x18_for_return( ucontext );
#endif
    }
}


/**********************************************************************
 *		usr2_handler
 *
 * Handler for SIGUSR2, used to set a thread context.
 */
static void usr2_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    struct syscall_frame *frame = get_syscall_frame();
    ucontext_t *context = sigcontext;
    DWORD i;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
#endif

    if (!is_inside_syscall( SP_sig(context) ))
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( context );
#endif
        return;
    }

    FP_sig(context)     = frame->fp;
    LR_sig(context)     = frame->lr;
    SP_sig(context)     = frame->sp;
    PC_sig(context)     = frame->pc;
    PSTATE_sig(context) = frame->cpsr;
    for (i = 0; i <= 28; i++) REGn_sig( i, context ) = frame->x[i];

#ifdef linux
    {
        struct fpsimd_context *fp = get_fpsimd_context( sigcontext );
        if (fp)
        {
            fp->fpcr = frame->fpcr;
            fp->fpsr = frame->fpsr;
            memcpy( fp->vregs, frame->v, sizeof(fp->vregs) );
        }
    }
#elif defined(__APPLE__)
    context->uc_mcontext->__ns.__fpcr = frame->fpcr;
    context->uc_mcontext->__ns.__fpsr = frame->fpsr;
    memcpy( context->uc_mcontext->__ns.__v, frame->v, sizeof(frame->v) );
#endif
}


/**********************************************************************
 *           get_thread_ldt_entry
 */
NTSTATUS get_thread_ldt_entry( HANDLE handle, THREAD_DESCRIPTOR_INFORMATION *info, ULONG len )
{
    return STATUS_NOT_IMPLEMENTED;
}


/**********************************************************************
 *             signal_init_threading
 */
void signal_init_threading(void)
{
}


/**********************************************************************
 *             signal_alloc_thread
 */
NTSTATUS signal_alloc_thread( TEB *teb )
{
    return STATUS_SUCCESS;
}


/**********************************************************************
 *             signal_free_thread
 */
void signal_free_thread( TEB *teb )
{
}


/**********************************************************************
 *		signal_init_process
 */
void signal_init_process(void)
{
    struct sigaction sig_act;
    struct ntdll_thread_data *thread_data = ntdll_get_thread_data();
    void *kernel_stack = (char *)thread_data->kernel_stack + kernel_stack_size;

    thread_data->syscall_frame = (struct syscall_frame *)kernel_stack - 1;

    signal_alloc_thread( NtCurrentTeb() );

#ifdef WINE_IOS
    /* Create TLS key for TEB storage (used by x18 binary patcher trampolines) */
    if (!ios_teb_tls_key_created)
    {
        pthread_key_create(&ios_teb_tls_key, NULL);
        ios_teb_tls_key_created = 1;
    }
#endif

    sig_act.sa_mask = server_block_set;
    sig_act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

    sig_act.sa_sigaction = int_handler;
    if (sigaction( SIGINT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = fpe_handler;
    if (sigaction( SIGFPE, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = abrt_handler;
    if (sigaction( SIGABRT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = quit_handler;
    if (sigaction( SIGQUIT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr1_handler;
    if (sigaction( SIGUSR1, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr2_handler;
    if (sigaction( SIGUSR2, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = trap_handler;
    if (sigaction( SIGTRAP, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = segv_handler;
    if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = ill_handler;
    if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = bus_handler;
    if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
    return;

 error:
    perror("sigaction");
    exit(1);
}


/***********************************************************************
 *           syscall_dispatcher_return_slowpath
 */
void syscall_dispatcher_return_slowpath(void)
{
    raise( SIGUSR2 );
}

/***********************************************************************
 *           init_syscall_frame
 */
void init_syscall_frame( LPTHREAD_START_ROUTINE entry, void *arg, BOOL suspend, TEB *teb )
{
    struct syscall_frame *frame = ((struct ntdll_thread_data *)&teb->GdiTebBatch)->syscall_frame;
    CONTEXT *ctx, context = { CONTEXT_ALL };
    I386_CONTEXT *i386_context;
    ARM_CONTEXT *arm_context;

    context.X0  = (DWORD64)entry;
    context.X1  = (DWORD64)arg;
    context.X18 = (DWORD64)teb;
    context.Sp  = (DWORD64)teb->Tib.StackBase;
    context.Pc  = (DWORD64)IOS_PFUNC(RtlUserThreadStart);

    if ((i386_context = get_cpu_area( IMAGE_FILE_MACHINE_I386 )))
    {
        XMM_SAVE_AREA32 *fpu = (XMM_SAVE_AREA32 *)i386_context->ExtendedRegisters;
        i386_context->ContextFlags = CONTEXT_I386_ALL;
        i386_context->Eax = (ULONG_PTR)entry;
        i386_context->Ebx = (arg == peb ? (ULONG_PTR)wow_peb : (ULONG_PTR)arg);
        i386_context->Esp = get_wow_teb( teb )->Tib.StackBase - 16;
        i386_context->Eip = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        i386_context->SegCs = 0x23;
        i386_context->SegDs = 0x2b;
        i386_context->SegEs = 0x2b;
        i386_context->SegFs = 0x53;
        i386_context->SegGs = 0x2b;
        i386_context->SegSs = 0x2b;
        i386_context->EFlags = 0x202;
        fpu->ControlWord = 0x27f;
        fpu->MxCsr = 0x1f80;
        fpux_to_fpu( &i386_context->FloatSave, fpu );
    }
    else if ((arm_context = get_cpu_area( IMAGE_FILE_MACHINE_ARMNT )))
    {
        arm_context->ContextFlags = CONTEXT_ARM_ALL;
        arm_context->R0 = (ULONG_PTR)entry;
        arm_context->R1 = (arg == peb ? (ULONG_PTR)wow_peb : (ULONG_PTR)arg);
        arm_context->Sp = get_wow_teb( teb )->Tib.StackBase;
        arm_context->Pc = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        if (arm_context->Pc & 1) arm_context->Cpsr |= 0x20; /* thumb mode */
    }

    if (suspend)
    {
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING | CONTEXT_EXCEPTION_ACTIVE;
        wait_suspend( &context );
    }

    ctx = (CONTEXT *)((ULONG_PTR)context.Sp & ~15) - 1;
    *ctx = context;
    ctx->ContextFlags = CONTEXT_FULL;
    signal_set_full_context( ctx );

    frame->sp    = (ULONG64)ctx;
    frame->pc    = (ULONG64)IOS_PFUNC(LdrInitializeThunk);
    frame->x[0]  = (ULONG64)ctx;
    frame->x[18] = (ULONG64)teb;

#ifdef WINE_IOS
    /* Translate PE code addresses to JIT pool addresses.
     * On iOS/TXM, PE code pages can't be made executable. The code was
     * copied to the JIT pool by mprotect_exec. Redirect PC to execute
     * from the JIT pool's original RX address.
     *
     * IMPORTANT: fixup_for_fastpath must be called AFTER this redirect,
     * so frame->x[16] == frame->pc (JIT pool address). Otherwise the
     * fastpath check fails and the slowpath (SIGUSR2) is taken, which
     * relies on iOS kernel restoring X18 from ucontext — but iOS
     * overrides X18 (platform register) on signal return. */
    {
        extern void *ios_jit_translate_addr(void *addr);
        void *orig_pc = (void *)(uintptr_t)frame->pc;
        void *jit_pc = ios_jit_translate_addr(orig_pc);
        if (jit_pc != orig_pc)
        {
            frame->pc = (ULONG64)(uintptr_t)jit_pc;
            ERR("init_syscall_frame: redirected PC %p → %p (JIT pool)\n", orig_pc, jit_pc);
        }
    }
#endif

    syscall_frame_fixup_for_fastpath( frame );

#ifdef WINE_IOS
    /* Save TEB for signal handler recovery */
    ios_teb_for_signals = (uintptr_t)teb;

    /* Store TEB in pthread TLS slot — accessible via TPIDRRO_EL0 which
     * iOS preserves across context switches. TPIDR_EL0 is NOT safe (iOS zeros it).
     * The x18 binary patcher rewrites PE code to read TEB from this TLS slot. */
    {
        extern pthread_key_t ios_teb_tls_key;
        extern int ios_teb_tls_slot_offset;
        pthread_setspecific(ios_teb_tls_key, teb);
        /* Also compute the raw TSD slot offset for the patcher's trampolines */
        if (ios_teb_tls_slot_offset == 0)
        {
            uintptr_t tsd_base;
            __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base));
            tsd_base &= ~7ULL;
            /* Find our TEB in the TSD array */
            for (int s = 0; s < 512; s++)
            {
                if (*(void **)(tsd_base + s * 8) == teb)
                {
                    ios_teb_tls_slot_offset = s * 8;
                    ERR("init_syscall_frame: TEB at TSD slot %d (offset 0x%x from TPIDRRO_EL0)\n",
                        s, ios_teb_tls_slot_offset);
                    break;
                }
            }
        }
    }

    /* Allocate per-thread trampoline slot in JIT pool */
    {
        extern int ios_jit_alloc_trampoline_slot(void);
        extern void ios_jit_set_teb_slot(int slot, uintptr_t teb);
        extern void *ios_jit_get_trampoline(int slot);

        ios_my_slot = ios_jit_alloc_trampoline_slot();
        ios_jit_set_teb_slot(ios_my_slot, (uintptr_t)teb);
        ios_my_trampoline = ios_jit_get_trampoline(ios_my_slot);
        ERR("init_syscall_frame: allocated trampoline slot %d, tramp=%p, teb=%p\n",
            ios_my_slot, ios_my_trampoline, teb);
    }

    /* iOS x18 workaround: The kernel zeroes x18 on context switches.
     * Pages 0-0x1FFF are readable on this device (return 0) but are NOT
     * a VM mapping (mach_vm_region shows first region at ~0x104000000).
     * The readable pages are hardware/firmware behavior that can't be
     * modified via mach_vm_protect/deallocate.
     *
     * When x18=0, [x18+0x60] silently returns PEB=0 instead of faulting.
     * Derived registers get corrupted before SEGV fires, making the
     * trampoline retry useless.
     *
     * Solution: CREATE a VM mapping at address 0 containing TEB data.
     * This overrides the hardware zero-page behavior. When x18=0,
     * [x18+offset] reads real TEB data from our mapping.
     * If all mapping approaches fail, the Mach exception handler
     * is the last resort for x18 restoration. */
    /* 2026-07-03: attempt the page0 chain ONCE PER PROCESS, not per thread.
     * Page 0 is process-global (and can only hold one thread's TEB anyway),
     * so re-running M1-M8 on every new thread only re-fails. Worse, the M8
     * debugger BRK is FATAL on threads created after the debugger detaches:
     * with no debugger, the BRK trap unwinds through a handler chain that
     * (with x18=0 on a fresh thread) calls a raw non-executable ntdll PE
     * address → undispatchable BUS → NtTerminateProcess. Observed killing
     * Thumper's worker-thread spawn at ~2:30 (thread 0054, splash wall). */
    static int ios_page0_attempted = 0;
    if (ios_page0_attempted) {
        ERR("page0: already attempted by first thread — skipping (Mach handler covers x18=0)\n");
    } else {
        ios_page0_attempted = 1;
        kern_return_t kr;
        int mapped = 0;
        uintptr_t teb_page = (uintptr_t)teb & ~0x3FFFULL;
        uintptr_t teb_off = (uintptr_t)teb - teb_page;

        /* Diagnostic: what's at address 0 */
        mach_vm_address_t region_addr = 0;
        mach_vm_size_t region_size = 0;
        vm_region_basic_info_data_64_t rinfo = {0};
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name = MACH_PORT_NULL;
        kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rinfo,
                            &info_count, &obj_name);
        ERR("page0: first_region=%p size=0x%llx prot=%d/%d kr=%d teb=%p teb_page=%p off=0x%lx\n",
            (void*)region_addr, (unsigned long long)region_size,
            rinfo.protection, rinfo.max_protection, kr,
            teb, (void*)teb_page, (unsigned long)teb_off);

        /* M1: mach_vm_allocate at 0 with VM_FLAGS_FIXED */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_allocate(mach_task_self(), &target, 0x4000, VM_FLAGS_FIXED);
            ERR("page0 M1 allocate(FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 1;
            }
        }

        /* M2: mach_vm_map anonymous RW at 0, FIXED|OVERWRITE */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                             MACH_PORT_NULL, 0, FALSE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_INHERIT_NONE);
            ERR("page0 M2 map(RW,FIXED|OVERWRITE): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 2;
            }
        }

        /* M3: mach_vm_map anonymous RW at 0, FIXED only (no OVERWRITE) */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                             VM_FLAGS_FIXED,
                             MACH_PORT_NULL, 0, FALSE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_INHERIT_NONE);
            ERR("page0 M3 map(RW,FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 3;
            }
        }

        /* M4: mach_vm_remap TEB page at 0 (shared mirror) */
        if (!mapped) {
            mach_vm_address_t target = 0;
            vm_prot_t cur_prot, max_prot;
            kr = mach_vm_remap(mach_task_self(), &target, 0x4000, 0,
                               VM_FLAGS_FIXED, mach_task_self(),
                               (mach_vm_address_t)teb_page, FALSE,
                               &cur_prot, &max_prot, VM_INHERIT_NONE);
            ERR("page0 M4 remap(FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) mapped = 4;
        }

        /* M5: memory entry + mach_vm_map */
        if (!mapped) {
            memory_object_size_t entry_size = 0x4000;
            mach_port_t mem_entry = MACH_PORT_NULL;
            kr = mach_make_memory_entry_64(mach_task_self(), &entry_size,
                (mach_vm_address_t)teb_page,
                VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_SHARE,
                &mem_entry, MACH_PORT_NULL);
            ERR("page0 M5 mem_entry: kr=%d\n", kr);
            if (kr == KERN_SUCCESS) {
                mach_vm_address_t target = 0;
                kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                    VM_FLAGS_FIXED,
                    mem_entry, 0, FALSE,
                    VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_NONE);
                ERR("page0 M5 map: kr=%d target=%p\n", kr, (void*)target);
                if (kr == KERN_SUCCESS && target == 0) mapped = 5;
                mach_port_deallocate(mach_task_self(), mem_entry);
            }
        }

        /* M6: mmap MAP_FIXED at 0 */
        if (!mapped) {
            void *p = mmap(0, 0x4000, PROT_READ | PROT_WRITE,
                           MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
            ERR("page0 M6 mmap(RW,FIXED): p=%p errno=%d\n", p, p == MAP_FAILED ? errno : 0);
            if (p == (void*)0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mprotect(0, 0x4000, PROT_READ);
                mapped = 6;
            }
        }

        /* M7: vm_allocate (32-bit API) at 0 */
        if (!mapped) {
            vm_address_t target = 0;
            kr = vm_allocate(mach_task_self(), &target, 0x4000, VM_FLAGS_FIXED);
            ERR("page0 M7 vm_allocate: kr=%d target=%p\n", kr, (void*)(uintptr_t)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 7;
            }
        }

        if (mapped) {
            /* Verify: compare PEB pointer from addr 0 vs real TEB */
            uint64_t peb0 = *(volatile uint64_t *)(teb_off + 0x60);
            uint64_t peb_real = *(volatile uint64_t *)((uintptr_t)teb + 0x60);
            ERR("TEB MAPPED at addr 0 (M%d)! peb@0x60=%p real=%p %s\n",
                mapped, (void*)peb0, (void*)peb_real,
                peb0 == peb_real ? "MATCH" : "MISMATCH");

            /* Check region again to confirm real mapping exists */
            region_addr = 0;
            info_count = VM_REGION_BASIC_INFO_COUNT_64;
            kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                                VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rinfo,
                                &info_count, &obj_name);
            ERR("page0 post-map: region=%p size=0x%llx prot=%d/%d\n",
                (void*)region_addr, (unsigned long long)region_size,
                rinfo.protection, rinfo.max_protection);
        }

        /* M8: Ask the debugger to write TEB data to page 0 via BRK #0xf00d cmd 3.
         * The debugger may have kernel privileges that the app doesn't.
         * Uses GDB M (memory write) command to write TEB data at address 0. */
        if (!mapped) {
            ERR("page0: trying debugger (BRK #0xf00d, x16=3)...\n");
            register uintptr_t x0_val __asm__("x0") = (uintptr_t)teb;
            register size_t x1_val __asm__("x1") = 0x4000;
            register uintptr_t x0_result __asm__("x0");
            __asm__ volatile(
                "mov x16, #3\n"
                "brk #0xf00d\n"
                : "=r"(x0_result)
                : "r"(x0_val), "r"(x1_val)
                : "x16", "memory"
            );
            ERR("page0 M8 debugger: result=%lu\n", (unsigned long)x0_result);
            if (x0_result == 1) {
                /* Verify: read PEB from address 0+offset */
                uintptr_t teb_off = (uintptr_t)teb - ((uintptr_t)teb & ~0x3FFFULL);
                uint64_t peb0 = *(volatile uint64_t *)(teb_off + 0x60);
                uint64_t peb_real = *(volatile uint64_t *)((uintptr_t)teb + 0x60);
                ERR("page0 M8 verify: peb@0x%lx=%p real=%p %s\n",
                    (unsigned long)(teb_off + 0x60), (void*)peb0, (void*)peb_real,
                    peb0 == peb_real ? "MATCH" : "MISMATCH");
                if (peb0 == peb_real) mapped = 8;
            }
        }

        if (!mapped) {
            ERR("ALL page0 mapping approaches FAILED (including debugger) — relying on Mach handler only\n");
        }
    }
    /* Register this thread with the shared Mach exception handler.
     * First call creates the handler thread; all calls register the thread. */
    ios_setup_mach_exception_handler( pthread_mach_thread_np(pthread_self()),
                                       (uintptr_t)teb, ios_my_trampoline );
    /* Give the handler thread a moment to start (only needed for first thread) */
    if (!ios_exc_thread_alive) usleep(10000);
    ERR("init_syscall_frame: mach exc thread alive=%d, slot=%d\n",
        ios_exc_thread_alive, ios_my_slot);

    ERR("init_syscall_frame: signals_total=%d before PE entry\n", ios_signal_total);
    ERR("init_syscall_frame: frame=%p pc=%p x0=%p sp=%p x18=%p restore_flags=0x%x\n",
        frame, (void*)(uintptr_t)frame->pc, (void*)(uintptr_t)frame->x[0],
        (void*)(uintptr_t)frame->sp, (void*)(uintptr_t)frame->x[18], frame->restore_flags);

    /* Note: SIGALRM x18 watchdog was tried but abandoned — too disruptive
     * for PE code execution. The zero-page silent read issue remains:
     * when x18=0, [x18+0x60] returns PEB=0 from the hardware zero page
     * without faulting, so the Mach handler can't intervene. */
#endif

    pthread_sigmask( SIG_UNBLOCK, &server_block_set, NULL );
}


/***********************************************************************
 *           signal_start_thread
 */
__ASM_GLOBAL_FUNC( signal_start_thread,
                   "stp x29, x30, [sp,#-0xc0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "add x5, x29, #0xc0\n\t"     /* syscall_cfa */
                   /* set syscall frame */
                   "ldr x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "cbnz x4, 1f\n\t"
                   "sub x4, sp, #0x330\n\t"     /* sizeof(struct syscall_frame) */
                   "str x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "1:\tstr wzr, [x4, #0x10c]\n\t" /* frame->restore_flags */
                   "stp xzr, x5, [x4, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   /* switch to kernel stack */
                   "mov sp, x4\n\t"
                   "bl " __ASM_NAME("init_syscall_frame") "\n\t"
#if 0 /* WINE_IOS: use standard dispatcher_return which loads ALL registers
       * and routes through the TEB trampoline on iOS */
#else
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return")
#endif
                   )


/***********************************************************************
 *           __wine_syscall_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                   "hint 34\n\t" /* bti c */
#ifdef WINE_IOS
                   /* iOS zeros x18 on context switches. Load TEB from TPIDRRO_EL0
                    * (pthread TLS) which iOS preserves. Fix x18 for frame saves. */
                   "mrs x10, TPIDRRO_EL0\n\t"
                   "and x10, x10, #~7\n\t"       /* clear CPU number bits */
                   "adrp x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGE\n\t"
                   "ldr w11, [x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGEOFF]\n\t"
                   "ldr x18, [x10, x11]\n\t"     /* x18 = TEB from TLS slot */
#endif
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "mov x19, sp\n\t"
                   "stp x9, x19, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "str w8, [x10, #0x120]\n\t"
                   "mrs x9, FPCR\n\t"
                   "str w9, [x10, #0x128]\n\t"
                   "mrs x9, FPSR\n\t"
                   "str w9, [x10, #0x12c]\n\t"
                   "stp q0,  q1,  [x10, #0x130]\n\t"
                   "stp q2,  q3,  [x10, #0x150]\n\t"
                   "stp q4,  q5,  [x10, #0x170]\n\t"
                   "stp q6,  q7,  [x10, #0x190]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "stp q16, q17, [x10, #0x230]\n\t"
                   "stp q18, q19, [x10, #0x250]\n\t"
                   "stp q20, q21, [x10, #0x270]\n\t"
                   "stp q22, q23, [x10, #0x290]\n\t"
                   "stp q24, q25, [x10, #0x2b0]\n\t"
                   "stp q26, q27, [x10, #0x2d0]\n\t"
                   "stp q28, q29, [x10, #0x2f0]\n\t"
                   "stp q30, q31, [x10, #0x310]\n\t"
                   "mov x22, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x22, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "and x20, x8, #0xfff\n\t"    /* syscall number */
                   "ubfx x21, x8, #12, #2\n\t"  /* syscall table number */
                   "ldr x16, [x18, #0x370]\n\t" /* thread_data->syscall_table */
                   "add x21, x16, x21, lsl #5\n\t"
                   "ldr x16, [x21, #16]\n\t"    /* table->ServiceLimit */
                   "cmp x20, x16\n\t"
                   "bcs " __ASM_LOCAL_LABEL("bad_syscall") "\n\t"
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w9, [x16, x20]\n\t"
                   "subs x9, x9, #64\n\t"
                   "bls 2f\n\t"
                   "sub sp, sp, x9\n\t"
                   "tbz x9, #3, 1f\n\t"
                   "sub sp, sp, #8\n"
                   "1:\tsub x9, x9, #8\n\t"
                   "ldr x10, [x19, x9]\n\t"
                   "str x10, [sp, x9]\n\t"
                   "cbnz x9, 1b\n"
                   "2:\tldr x16, [x21]\n\t"     /* table->ServiceTable */
                   "ldr x23, [x16, x20, lsl 3]\n\t"
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall") "\n\t"
                   "blr x23\n\t"
                   "mov sp, x22\n"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") ":\n\t"
#ifdef WINE_IOS
                   /* Trace: capture frame->x[18] and frame->pc before they are loaded */
                   "ldr x10, [sp, #0x90]\n\t"   /* frame->x[18] - will become x18 */
                   "adrp x11, " __ASM_NAME("g_wine_return_x18") "@PAGE\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_x18") "@PAGEOFF]\n\t"
                   "ldr x10, [sp, #0x100]\n\t"  /* frame->pc - will become ret target */
                   "adrp x11, " __ASM_NAME("g_wine_return_pc") "@PAGE\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_pc") "@PAGEOFF]\n\t"
                   "adrp x11, " __ASM_NAME("g_wine_return_count") "@PAGE\n\t"
                   "ldr x10, [x11, " __ASM_NAME("g_wine_return_count") "@PAGEOFF]\n\t"
                   "add x10, x10, #1\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_count") "@PAGEOFF]\n\t"
                   /* ring buffer: store frame->pc (at sp+0x100) into ring[idx & 7] */
                   "ldr x10, [sp, #0x100]\n\t"          /* frame->pc */
                   "adrp x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGE\n\t"
                   "ldr w12, [x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGEOFF]\n\t"
                   "and w13, w12, #7\n\t"                /* idx & 7 */
                   "add w12, w12, #1\n\t"
                   "str w12, [x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGEOFF]\n\t"
                   "adrp x11, " __ASM_NAME("g_wine_return_ring") "@PAGE\n\t"
                   "add x11, x11, " __ASM_NAME("g_wine_return_ring") "@PAGEOFF\n\t"
                   "str x10, [x11, x13, lsl #3]\n\t"    /* ring[idx&7] = frame->pc */
#endif
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "tbz x16, #1, 2f\n\t"        /* CONTEXT_INTEGER */
                   "ldp x12, x13, [sp, #0x80]\n\t" /* frame->x[16..17] */
                   "ldp x14, x15, [sp, #0xf8]\n\t" /* frame->sp, frame->pc */
                   "cmp x12, x15\n\t"              /* frame->x16 == frame->pc? */
                   "ccmp x13, x14, #0, eq\n\t"     /* frame->x17 == frame->sp? */
                   "beq 1f\n\t"                    /* take slowpath if unequal */
                   "bl " __ASM_NAME("syscall_dispatcher_return_slowpath") "\n"
                   "1:\tldp x0, x1, [sp, #0x00]\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x8, x9, [sp, #0x40]\n\t"
                   "ldp x10, x11, [sp, #0x50]\n\t"
                   "ldp x12, x13, [sp, #0x60]\n\t"
                   "ldp x14, x15, [sp, #0x70]\n"
                   "2:\tldp x18, x19, [sp, #0x90]\n\t"
#ifdef WINE_IOS
                   /* TPIDR_EL0 not used — iOS zeros it. TEB stored via pthread TLS (TPIDRRO_EL0). */
#endif
                   "ldp x20, x21, [sp, #0xa0]\n\t"
                   "ldp x22, x23, [sp, #0xb0]\n\t"
                   "ldp x24, x25, [sp, #0xc0]\n\t"
                   "ldp x26, x27, [sp, #0xd0]\n\t"
                   "ldp x28, x29, [sp, #0xe0]\n\t"
                   "tbz x16, #2, 1f\n\t"        /* CONTEXT_FLOATING_POINT */
                   "ldp q0,  q1,  [sp, #0x130]\n\t"
                   "ldp q2,  q3,  [sp, #0x150]\n\t"
                   "ldp q4,  q5,  [sp, #0x170]\n\t"
                   "ldp q6,  q7,  [sp, #0x190]\n\t"
                   "ldp q8,  q9,  [sp, #0x1b0]\n\t"
                   "ldp q10, q11, [sp, #0x1d0]\n\t"
                   "ldp q12, q13, [sp, #0x1f0]\n\t"
                   "ldp q14, q15, [sp, #0x210]\n\t"
                   "ldp q16, q17, [sp, #0x230]\n\t"
                   "ldp q18, q19, [sp, #0x250]\n\t"
                   "ldp q20, q21, [sp, #0x270]\n\t"
                   "ldp q22, q23, [sp, #0x290]\n\t"
                   "ldp q24, q25, [sp, #0x2b0]\n\t"
                   "ldp q26, q27, [sp, #0x2d0]\n\t"
                   "ldp q28, q29, [sp, #0x2f0]\n\t"
                   "ldp q30, q31, [sp, #0x310]\n\t"
                   "ldr w17, [sp, #0x128]\n\t"
                   "msr FPCR, x17\n\t"
                   "ldr w17, [sp, #0x12c]\n\t"
                   "msr FPSR, x17\n"
                   "1:\tldp x16, x17, [sp, #0x100]\n\t"
                   "msr NZCV, x17\n\t"
                   /* x18 was restored from frame->x[18] at label 2 above.
                    * This path does NOT go through sigreturn, so x18 survives.
                    * If a context switch zeroes x18 before PE code runs,
                    * the Mach exception handler fixes it via per-thread trampoline. */
                   "ldp x30, x17, [sp, #0xf0]\n\t"
                   /* switch to user stack */
                   "mov sp, x17\n\t"
                   "ret x16\n"

                   __ASM_LOCAL_LABEL("trace_syscall") ":\n\t"
                   "stp x0, x1, [sp, #-0x40]!\n\t"
                   "stp x2, x3, [sp, #0x10]\n\t"
                   "stp x4, x5, [sp, #0x20]\n\t"
                   "stp x6, x7, [sp, #0x30]\n\t"
                   "mov x0, x8\n\t"             /* id */
                   "mov x1, sp\n\t"             /* args */
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w2, [x16, x20]\n\t"    /* len */
                   "bl " __ASM_NAME("trace_syscall") "\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x0, x1, [sp], #0x40\n\t"
                   "blr x23\n"
                   "mov sp, x22\n"

                   __ASM_LOCAL_LABEL("trace_syscall_ret") ":\n\t"
                   "mov x21, x0\n\t"            /* retval */
                   "ldr w0, [sp, #0x120]\n\t"   /* frame->syscall_id */
                   "mov x1, x21\n\t"            /* retval */
                   "bl " __ASM_NAME("trace_sysret") "\n\t"
                   "mov x0, x21\n\t"            /* retval */
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n"

                   __ASM_LOCAL_LABEL("bad_syscall") ":\n\t"
                   "mov x0, #0xc0000000\n\t"    /* STATUS_INVALID_SYSTEM_SERVICE */
                   "movk x0, #0x001c\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )

__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher_return,
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall_ret") "\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )


/***********************************************************************
 *           __wine_unix_call_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                   "hint 34\n\t" /* bti c */
#ifdef WINE_IOS
                   "mrs x10, TPIDRRO_EL0\n\t"
                   "and x10, x10, #~7\n\t"
                   "adrp x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGE\n\t"
                   "ldr w11, [x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGEOFF]\n\t"
                   "ldr x18, [x10, x11]\n\t"     /* x18 = TEB from TLS */
#endif
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "mov x9, sp\n\t"
                   "stp x30, x9, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "mov x19, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x19, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "ldr x16, [x0, x1, lsl 3]\n\t"
                   "mov x0, x2\n\t"             /* args */
                   "blr x16\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "cbnz w16, " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   "ldp x18, x19, [sp, #0x90]\n\t"
                   /* iOS-Mythic 2026-07-04: REMOVED `msr TPIDR_EL0, x18`
                    * ("keep TPIDR_EL0 in sync"). Nothing of ours reads
                    * TPIDR_EL0 — every TEB recovery path (dispatchers, x18
                    * patcher trampolines, Mach handler) uses TPIDRRO_EL0 +
                    * TSD slot; the patcher header comment claiming
                    * TPIDR_EL0 was stale. Writing an OS-owned per-thread
                    * register on every unix-call return is pure risk:
                    * libsystem_malloc died with corrupted per-thread zone
                    * state (Metal texture allocs, 3 runs) right after
                    * UNIXCALL-DIRECT multiplied direct returns. */
                   "ldp x16, x17, [sp, #0xf8]\n\t"
                   /* switch to user stack */
                   "mov sp, x16\n\t"
                   "ret x17" )

#endif  /* __aarch64__ */

/* ============================================================ *
 * [thread-stacks] all-thread stack sampler — diagnoses wedged wine
 * threads (S2: explorer main leaves its message pump and blocks
 * forever; [srv-queues] showed wake_mask=0 with 20 posted messages
 * pending). Called from an app-side GCD timer (Winios.m) so it keeps
 * firing even when every wine thread is stuck. Samples WITHOUT
 * suspending — racy pc/fp reads are acceptable for stuck-thread
 * triage; a blocked thread's state is stable anyway.
 * ============================================================ */
/* Best-effort PE module name from the export directory at pe_base (the
 * original unix-view image stays mapped). Returns "(exe)" for images
 * without exports, "?" when headers look wrong. */
static const char *ios_pe_module_name( uint64_t base )
{
    const unsigned char *p = (const unsigned char *)(uintptr_t)base;
    uint32_t e_lfanew, exp_rva, name_rva;

    if (!base) return "?";
    if (p[0] != 'M' || p[1] != 'Z') return "?";
    e_lfanew = *(const uint32_t *)(p + 0x3c);
    if (e_lfanew == 0 || e_lfanew > 0x1000) return "?";
    if (memcmp(p + e_lfanew, "PE\0\0", 4)) return "?";
    exp_rva = *(const uint32_t *)(p + e_lfanew + 0x88);   /* PE32+ export dir RVA */
    if (!exp_rva || exp_rva > 0x10000000) return "(exe)";
    name_rva = *(const uint32_t *)(p + exp_rva + 0x0c);
    if (!name_rva || name_rva > 0x10000000) return "(exe)";
    return (const char *)(p + name_rva);
}

void ios_dump_all_thread_stacks(void)
{
    thread_act_array_t threads;
    mach_msg_type_number_t count = 0, i;
    thread_t self = mach_thread_self();

    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS) return;
    fprintf(stderr, "[thread-stacks] ---- %u threads ----\n", count);
    for (i = 0; i < count; i++)
    {
        arm_thread_state64_t st;
        mach_msg_type_number_t st_count = ARM_THREAD_STATE64_COUNT;
        char tname[64] = "";
        pthread_t pt;
        Dl_info di;
        const char *img = "?", *sym = "?";
        uint64_t off, fp_walk;
        int fr;

        if (threads[i] == self) goto next;
        if (thread_get_state(threads[i], ARM_THREAD_STATE64, (thread_state_t)&st, &st_count) != KERN_SUCCESS)
            goto next;

        pt = pthread_from_mach_thread_np(threads[i]);
        if (pt) pthread_getname_np(pt, tname, sizeof(tname));

        off = st.__pc;
        if (dladdr((void*)(uintptr_t)st.__pc, &di))
        {
            if (di.dli_fname) { img = strrchr(di.dli_fname, '/'); img = img ? img + 1 : di.dli_fname; }
            if (di.dli_sname) { sym = di.dli_sname; off = st.__pc - (uint64_t)(uintptr_t)di.dli_saddr; }
        }
        fprintf(stderr, "[thread-stacks] port=0x%x \"%s\" pc=%s`%s+0x%llx\n",
                threads[i], tname, img, sym, (unsigned long long)off);
        {
            extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
            uint64_t mod = 0, pe_va = ios_jit_reverse_translate(st.__pc, &mod);
            if (pe_va)
                fprintf(stderr, "[thread-stacks]   pc is PE code: %.32s+0x%llx (base=0x%llx va=0x%llx)\n",
                        ios_pe_module_name(mod), (unsigned long long)(pe_va - mod),
                        (unsigned long long)mod, (unsigned long long)pe_va);
        }

        fp_walk = st.__fp;
        for (fr = 0; fr < 14 && fp_walk; fr++)
        {
            uint64_t frame_buf[2];
            mach_vm_size_t got_fw = 0;
            uint64_t ret_pc;

            if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)fp_walk, 16,
                                       (mach_vm_address_t)frame_buf, &got_fw) != KERN_SUCCESS || got_fw != 16)
                break;
            ret_pc = frame_buf[1] & 0x0000007fffffffffull;   /* strip PAC bits */
            if (ret_pc <= 0x4000) break;
            img = "?"; sym = "?"; off = ret_pc;
            if (dladdr((void*)(uintptr_t)ret_pc, &di))
            {
                if (di.dli_fname) { img = strrchr(di.dli_fname, '/'); img = img ? img + 1 : di.dli_fname; }
                if (di.dli_sname) { sym = di.dli_sname; off = ret_pc - (uint64_t)(uintptr_t)di.dli_saddr; }
            }
            {
                extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                uint64_t mod = 0, pe_va = ios_jit_reverse_translate(ret_pc, &mod);
                if (pe_va)
                    fprintf(stderr, "[thread-stacks]   bt[%d] PE %.32s+0x%llx (va=0x%llx)\n",
                            fr, ios_pe_module_name(mod), (unsigned long long)(pe_va - mod),
                            (unsigned long long)pe_va);
                else
                    fprintf(stderr, "[thread-stacks]   bt[%d] %s`%s+0x%llx\n", fr, img, sym, (unsigned long long)off);
            }
            fp_walk = frame_buf[0];
        }
next:
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    mach_port_deallocate(mach_task_self(), self);
    fflush(stderr);
}
