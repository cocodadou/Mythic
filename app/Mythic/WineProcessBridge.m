// WineProcessBridge.m - Initialize Wine's ntdll Unix-side on iOS
// This calls __wine_main() to bootstrap the Wine process, connecting
// to the already-running wineserver thread.

#import <Foundation/Foundation.h>
#import <os/log.h>
#import <pthread.h>
/* AVFoundation: AVAudioSession activation for the Tier-2 audio driver
 * (audio_null_ios.c RemoteIO backend). AudioToolbox: pulls the framework
 * in via autolink — the static-lib driver code can't autolink itself. */
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <stdlib.h>
#include <errno.h>

#include "WineProcessBridge.h"
#include "WineServerBridge.h"
#include "PrefixExtractor.h"
#include "FEXBridge.h"  // fex_get_jit_write_offset()

// Thread-local globals for wine_ios_exit longjmp (used by wine_ios_exit.h shim in ntdll)
// Each Wine "process" thread has its own jmpbuf so child processes can exit independently.
_Thread_local jmp_buf wine_ios_exit_jmpbuf;
_Thread_local volatile int wine_ios_exit_code = 0;
_Thread_local pthread_t wine_ios_main_thread;
_Thread_local int wine_ios_exit_initialized = 0;


static os_log_t wine_proc_log(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.mythic.emulator", "wine-proc"); });
    return log;
}

#define LOG(fmt, ...) os_log(wine_proc_log(), "[WineProc] " fmt, ##__VA_ARGS__)

// Wine's main entry point (from ntdll unix loader.c, statically linked)
extern void __wine_main(int argc, char *argv[]);

// File-based logging (from server_ios.c)
extern void wine_log_set_file(const char *path);

static pthread_t g_wine_thread;
static volatile int g_wine_running = 0;
static char *g_prefix_path = NULL;

static void *wine_process_thread(void *arg) {
    @autoreleasepool {
        /* Perf: the guest main thread runs ON this pthread. Promote to
         * USER_INTERACTIVE so it schedules on P-cores with minimal kernel
         * timer coalescing (same rationale as start_thread in
         * thread_ios.c — default QoS costs tens of ms of sleep leeway). */
        pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
        LOG("Wine process thread started");

        // Seed prefix from bundled template on first launch (Proton-style).
        // The presence of .update-timestamp means wineboot has already run
        // (either for real or via our pre-seed), so the ntdll-side
        // run_wineboot will skip the launch path.
        {
            NSString *prefix = [NSString stringWithUTF8String:g_prefix_path];
            NSString *stamp = [prefix stringByAppendingPathComponent:@".update-timestamp"];
            NSFileManager *fm = [NSFileManager defaultManager];
            if (![fm fileExistsAtPath:stamp]) {
                NSString *tgz = [[NSBundle mainBundle] pathForResource:@"prefix-template" ofType:@"tar.gz"];
                if (!tgz) {
                    LOG("prefix-template.tar.gz missing from bundle!");
                } else {
                    LOG("Seeding prefix from %{public}s", tgz.UTF8String);
                    if (mythic_extract_prefix_tgz(tgz.UTF8String, g_prefix_path) != 0) {
                        LOG("prefix extraction FAILED");
                    } else {
                        LOG("prefix seeded to %{public}s", g_prefix_path);
                    }
                }
            }

            // (Re)create dosdevices/c: -> ../drive_c. The tarball omits
            // dosdevices because Mac's z: -> / is wrong here.
            NSString *dosdev = [prefix stringByAppendingPathComponent:@"dosdevices"];
            [fm createDirectoryAtPath:dosdev withIntermediateDirectories:YES attributes:nil error:nil];
            NSString *cLink = [dosdev stringByAppendingPathComponent:@"c:"];
            [fm removeItemAtPath:cLink error:nil];
            [fm createSymbolicLinkAtPath:cLink withDestinationPath:@"../drive_c" error:nil];
        }

        // Set environment for Wine
        setenv("WINEPREFIX", g_prefix_path, 1);
        setenv("HOME", g_prefix_path, 1);

        // Skip check_command_line / reexec_loader
        setenv("WINELOADERNOEXEC", "1", 1);

        // Set DLL search path to app bundle (contains aarch64-windows/ with PE DLLs)
        {
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            setenv("WINEDLLPATH", bundlePath.UTF8String, 1);
            LOG("WINEDLLPATH=%{public}s", bundlePath.UTF8String);
        }

        /* Wine trace channels.
         *
         * 2026-05-19 perf pivot: the verbose default (err+all, fixme+all,
         * warn+module, warn+file, trace+process, trace+module, trace+loaddll,
         * trace+loadorder, trace+win, trace+user32, trace+syscall, trace+file)
         * was generating ~220 KB/sec of log writes — the dominant source of
         * the 1.35s-per-frame menu rendering. trace+syscall + trace+file alone
         * are likely 90%+ of the volume (every Nt* call writes 3-5 log lines).
         *
         * Default is now PERF: only err+all (so we still see real failures).
         * For debugging, set MYTHIC_DEBUG_VERBOSE=1 in the environment to
         * restore the full trace channel set. */
        {
            const char *verbose = getenv("MYTHIC_DEBUG_VERBOSE");
            if (verbose && *verbose && *verbose != '0') {
                setenv("WINEDEBUG", "err+all,fixme+all,warn+module,warn+file,trace+process,trace+module,trace+loaddll,trace+loadorder,trace+win,trace+user32,trace+syscall,trace+file", 1);
                LOG("WINEDEBUG = verbose (MYTHIC_DEBUG_VERBOSE set)");
            } else {
                /* err+all keeps real failure messages, but subtract err+virtual
                 * because our iOS virtual_ios.c uses ERR() for informational
                 * traces ("iOS vm_protect RW+COPY OK", "iOS JIT: pool size",
                 * "iOS JIT: copied image"). Those produce thousands of lines
                 * per boot. Real failures in virtual_ios.c use distinctive
                 * FATAL/FAIL prefixes our app surfaces via other paths. */
                setenv("WINEDEBUG", "err+all,err-virtual", 1);
                LOG("WINEDEBUG = err+all,err-virtual (perf default — set MYTHIC_DEBUG_VERBOSE=1 for full trace)");
            }
        }

        // Phase 3D investigation: re-enabled. Investigation C concluded
        // wineserver dispatch is fine; the `ws_log drops at high rate`
        // artifact was the prior false signal. Now chasing a real bug:
        // get_desktop_window's returned HWND fails get_user_object lookup
        // when create_window receives it as req->parent.
        setenv("MYTHIC_WIN32U", "1", 1);

        /* 2026-07-05 quiet/release mode: disables the heavyweight
         * diagnostics — the PROF sampler (thread_suspends the game thread
         * ~500x/s), per-present log lines (100+/s at RAW rates), winios
         * poll heartbeat. Counters (present count for the FPS overlay,
         * machexc, srvw) keep ticking; ERR-level and boot logging are
         * untouched. Worth a few %% of frame time and, more importantly,
         * HEAT — thermals are what cap ProMotion at 60. COMMENT THIS OUT
         * for diagnostic/profiling sessions. */
        setenv("MYTHIC_QUIET", "1", 1);

        /* task #34 share/purge-probe experiments CONCLUDED 2026-07-14
         * (remap-sharing dead; pool not purgeable; ml76 wall = mismatched
         * MADV_FREE/MADV_FREE_REUSE pair). Probe machinery stays in
         * ntdll-unix, gated on MYTHIC_SHARE_PROBE — set it here to re-run. */

        /* 2026-07-05 audio: activate the AVAudioSession before Wine boots
         * so the RemoteIO unit in the mmdevapi driver can start. Playback
         * category = ignores silent switch (it's a game). */
        {
            NSError *aerr = nil;
            AVAudioSession *session = [AVAudioSession sharedInstance];
            [session setCategory:AVAudioSessionCategoryPlayback error:&aerr];
            if (aerr) LOG("AVAudioSession setCategory failed: %{public}s",
                          aerr.localizedDescription.UTF8String);
            aerr = nil;
            [session setActive:YES error:&aerr];
            if (aerr) LOG("AVAudioSession setActive failed: %{public}s",
                          aerr.localizedDescription.UTF8String);
            else LOG("AVAudioSession active: rate=%.0f latency=%.1fms",
                     session.sampleRate, session.outputLatency * 1000.0);
        }

        /* 2026-07-04 BISECT RESULT: arm A (this env set, all handler fixes
         * on) booted to menu at 17-18 FPS with the x18-access emulator
         * firing 135K+ times cleanly — handler fixes EXONERATED. The
         * libsystem_malloc death is specific to UNIXCALL-DIRECT. Env
         * removed; next crash run carries an fp-walk backtrace + malloc
         * prologue dump to name the Metal call handing free() a garbage
         * pointer. */

        /* 2026-07-04: MYTHIC_HEAL retried with XLATE-HOOK-REV in place and
         * STILL fatal — same C000001D libplatform (os_unfair_lock abort)
         * seconds after healing the ntdll dispatch-thunk VA at boot. One of
         * the rewritten slots has a consumer doing identity/offset math on
         * the PE VA, which no unwinder fix helps. Blanket healing is dead;
         * the fault-latency attack needs slot-level forensics (which slot
         * is the pure branch-feeder) or a writer-side fix. Healer stays
         * opt-in-off. */

        /* Steam game vars — Thumper queries SteamAppPath dozens of times in init
         * and uses it as base path for asset loading. Prior comment claimed
         * setenv didn't propagate to Wine's GetEnvironmentVariableW, but reading
         * env.c::get_initial_environment shows non-WINE/non-special vars DO
         * pass through (line 915 fall-through). Re-trying this empirically. */
        setenv("SteamAppPath", "C:\\Program Files\\Thumper", 1);
        setenv("SteamGameId", "356400", 1);  // Thumper's Steam app ID
        setenv("SteamAppId",  "356400", 1);
        LOG("setenv check: SteamAppPath=%{public}s SteamGameId=%{public}s",
            getenv("SteamAppPath"), getenv("SteamGameId"));

        /* iOS-Mythic 2026-07-02: publish the TRUE JIT-pool RX->RW offset to
         * xtajit64.dll (its own FEXCore copy reads this via getenv in
         * ProcessInit). Set HERE — beside SteamAppPath, the point where
         * Wine snapshots the environment — so it forwards reliably; setting
         * it in FEXBridge.mm::jit_pool_init was too early and did not reach
         * Wine's GetEnvironmentVariableW. jit_pool_init has already run by
         * now (fex_initialize is a prerequisite for launching the guest),
         * so the offset is available. */
        {
            int64_t jit_off = fex_get_jit_write_offset();
            if (jit_off != 0) {
                char off_str[32];
                snprintf(off_str, sizeof(off_str), "0x%llx", (unsigned long long)jit_off);
                setenv("MYTHIC_JIT_WRITE_OFFSET", off_str, 1);
                LOG("setenv MYTHIC_JIT_WRITE_OFFSET=%{public}s", off_str);
            } else {
                LOG("WARNING: fex_get_jit_write_offset() returned 0 — JIT pool not initialized?");
            }
        }

        /* iOS-Mythic: TSO stays ENABLED (default). The unaligned LDAR/LDAPR/
         * STLR backpatch is now in signal_arm64_ios.c's Mach handler, which
         * replicates FEX's HandleUnalignedAccess (Arm64.cpp:2072) so iOS
         * EXC_BAD_ACCESS faults get the same in-place LDAR→LDR+DMB_LD
         * recovery FEX does for Windows EXCEPTION_DATATYPE_MISALIGNMENT. */

        /* iOS-Mythic: a tiny stub steamclient64.dll is shipped in the game
         * directory (built from /tmp/steamclient_stub/stub.c). It exports
         * just VR_InitInternal (returns NULL) — that's the only function
         * CODEX64.dll imports from steamclient64. The real steamclient64.dll
         * (heavily packed, RWX self-modifying, unwind info v5) was
         * blowing up Wine's loader; the stub lets CODEX bind imports and
         * proceed without OpenVR support. Note: no WINEDLLOVERRIDES needed
         * — we just shipped a different file at the same path. */

        LOG("WINEPREFIX=%{public}s", g_prefix_path);

        // Set up file-based logging for Wine C code
        {
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *logPath = [docs stringByAppendingPathComponent:@"mythic-log.txt"];
            wine_log_set_file(logPath.UTF8String);
            LOG("Wine log file: %{public}s", logPath.UTF8String);
            /* Expose the app Documents dir to Wine code (e.g. for fex-jit-dump.bin) */
            setenv("MYTHIC_DOCS_DIR", docs.UTF8String, 1);
        }

        // Steam S0: root CA trust. iOS has no API to enumerate system
        // roots, so crypt32's unix rootstore (crypt32_unixlib_ios.c)
        // reads the bundled Mozilla CA set from this path instead.
        {
            NSString *caPath = [[NSBundle mainBundle] pathForResource:@"cacert" ofType:@"pem"];
            if (caPath) {
                setenv("MYTHIC_CA_BUNDLE", caPath.UTF8String, 1);
                LOG("CA bundle: %{public}s", caPath.UTF8String);
            } else {
                LOG("WARNING: cacert.pem missing from bundle — HTTPS cert verification will fail");
            }
        }

        // Redirect stderr AND stdout to log file so Wine debug output (WINEDEBUG)
        // and the guest program's printf are both captured.
        {
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *logPath2 = [docs stringByAppendingPathComponent:@"mythic-log.txt"];
            int logfd = open(logPath2.UTF8String, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (logfd >= 0) {
                dup2(logfd, STDERR_FILENO);
                dup2(logfd, STDOUT_FILENO);
                close(logfd);
            }
        }

        // Pick which exe to run (env var override, default = cube.exe).
        // Set MYTHIC_EXE=hello-x64.exe in env to launch the ARM64EC test path.
        const char *mythic_exe = getenv("MYTHIC_EXE");
        if (!mythic_exe || !*mythic_exe) mythic_exe = "cube.exe";
        // Heuristic: x86_64 guest exes (cube-x64, hello-x64, real games like
        // Thumper) need the arm64ec-windows bundle (ARM64EC hybrid system
        // DLLs that interop with FEX-translated x86_64 code). ARM64-native
        // tests (cube.exe) use the aarch64-windows bundle.
        // MYTHIC_USE_ARM64EC=1 forces the arm64ec path explicitly.
        // Otherwise: detect "x64" in the exe name (cube-x64, fib-x64, etc.)
        // OR a Win32 full path (real game launches typically need ARM64EC).
        const char *force_ec = getenv("MYTHIC_USE_ARM64EC");
        BOOL use_arm64ec = (force_ec && *force_ec == '1') ||
                           (strstr(mythic_exe, "x64") != NULL) ||
                           (strchr(mythic_exe, '\\') != NULL);
        const char *bundle_subdir = use_arm64ec ? "arm64ec-windows" : "aarch64-windows";
        LOG("Target exe: %{public}s (bundle=%{public}s)", mythic_exe, bundle_subdir);
        dprintf(STDERR_FILENO, "[WineProc] Target exe: %s (bundle=%s)\n", mythic_exe, bundle_subdir);

        // Ensure Wine prefix has system32 directory with DLLs from bundle
        {
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            NSString *dllSource = [bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:bundle_subdir]];
            NSString *prefix = [NSString stringWithUTF8String:g_prefix_path];
            NSString *sys32Dir = [prefix stringByAppendingPathComponent:@"drive_c/windows/system32"];
            NSFileManager *fm = [NSFileManager defaultManager];

            [fm createDirectoryAtPath:sys32Dir withIntermediateDirectories:YES attributes:nil error:nil];

            NSArray *dlls = [fm contentsOfDirectoryAtPath:dllSource error:nil];
            int linked = 0;
            for (NSString *dll in dlls) {
                NSString *src = [dllSource stringByAppendingPathComponent:dll];
                NSString *dst = [sys32Dir stringByAppendingPathComponent:dll];
                // Remove stale symlinks and re-create (bundle path changes on reinstall)
                [fm removeItemAtPath:dst error:nil];
                if ([fm createSymbolicLinkAtPath:dst withDestinationPath:src error:nil])
                    linked++;
            }
            LOG("Symlinked %d DLLs from %{public}s to %{public}s", linked, bundle_subdir, sys32Dir.UTF8String);
            dprintf(STDERR_FILENO, "[WineProc] Symlinked %d DLLs from %s -> sys32\n", linked, bundle_subdir);

            // X3 mixed-mode: also link NON-COLLIDING files from the other
            // bundle arch so cross-arch child exes resolve by Win32 path
            // (e.g. proc-test-x64.exe in an aarch64 desktop session).
            // Canonical DLL names (ntdll.dll, ...) already link to the
            // session's set above and are skipped here; children load their
            // system DLLs arch-correctly via WINEDLLPATH + pe_dir probing.
            {
                const char *other_subdir = use_arm64ec ? "aarch64-windows" : "arm64ec-windows";
                NSString *otherSource = [bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:other_subdir]];
                NSArray *others = [fm contentsOfDirectoryAtPath:otherSource error:nil];
                int crossLinked = 0;
                for (NSString *f in others) {
                    NSString *dst = [sys32Dir stringByAppendingPathComponent:f];
                    // fileExistsAtPath FOLLOWS symlinks: YES means the session
                    // (main) pass already linked this name to a resolvable
                    // file — that arch wins, leave it.
                    if ([fm fileExistsAtPath:dst]) continue;
                    // NO means absent OR a stale/dangling symlink left by a
                    // previous install (bundle UUID changed on reinstall).
                    // createSymbolicLink fails with EEXIST on a dangling link
                    // that still occupies the path — which silently left the
                    // -x64 files pointing at a dead bundle, so they vanished
                    // from Wine's dir enumeration. Clear then recreate, like
                    // the main pass does.
                    [fm removeItemAtPath:dst error:nil];
                    NSString *src = [otherSource stringByAppendingPathComponent:f];
                    if ([fm createSymbolicLinkAtPath:dst withDestinationPath:src error:nil])
                        crossLinked++;
                }
                dprintf(STDERR_FILENO, "[WineProc] Cross-linked %d non-colliding files from %s -> sys32\n",
                        crossLinked, other_subdir);
            }

            // X3c mixed-mode: full per-arch DLL farms. A cross-arch child's
            // private ntdll retries C:\windows\sysx64 (SysWOW64-style) when a
            // system32 name resolves to the session arch's binary — colliding
            // names (ucrtbase, kernel32, ...) always do. sysaa64 is the
            // mirror for the future inverse case (aarch64 child in an EC
            // session, e.g. rpcss under Steam).
            {
                struct { const char *farm; const char *arch; } farms[] = {
                    { "sysx64",  "arm64ec-windows" },
                    { "sysaa64", "aarch64-windows" },
                };
                for (int i = 0; i < 2; i++) {
                    NSString *farmDir = [prefix stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"drive_c/windows/%s", farms[i].farm]];
                    NSString *archSource = [bundlePath stringByAppendingPathComponent:
                        [NSString stringWithUTF8String:farms[i].arch]];
                    [fm createDirectoryAtPath:farmDir withIntermediateDirectories:YES attributes:nil error:nil];
                    NSArray *files = [fm contentsOfDirectoryAtPath:archSource error:nil];
                    int farmLinked = 0;
                    for (NSString *f in files) {
                        NSString *dst = [farmDir stringByAppendingPathComponent:f];
                        [fm removeItemAtPath:dst error:nil];  // self-heal stale links on reinstall
                        NSString *src = [archSource stringByAppendingPathComponent:f];
                        if ([fm createSymbolicLinkAtPath:dst withDestinationPath:src error:nil])
                            farmLinked++;
                    }
                    dprintf(STDERR_FILENO, "[WineProc] Farm %s: %d links -> %s\n",
                            farms[i].farm, farmLinked, farms[i].arch);
                }
            }

            // Layer Microsoft's real VC++ Runtime DLLs ON TOP of the ARM64EC
            // bundle (only for x86_64 guests). These overwrite Wine's stub
            // builtins — Wine then loads the real MS x86_64 implementation
            // (via FEX) instead of its partial ARM64EC reimplementation.
            //
            // Same pattern Proton/Winlator use: drop in the real concrt140 /
            // msvcp140 / vcruntime140 binaries from VC_redist.x64.exe so games
            // that exercise the full C++ runtime (parallel_for, atomic_wait,
            // <filesystem>, etc.) don't trip __wine_unimplemented stubs.
            if (use_arm64ec) {
                NSString *vcrtSource = [bundlePath stringByAppendingPathComponent:@"x86_64-vcruntime"];
                NSArray *vcrtDlls = [fm contentsOfDirectoryAtPath:vcrtSource error:nil];
                int vcrtLinked = 0, vcrtSkipped = 0;
                for (NSString *dll in vcrtDlls) {
                    /* NOTE 2026-07-03 (late): retried lifting BOTH exemptions
                     * below after the fast-write bisect, hoping trap-mode had
                     * fixed the corruption class (and to keep hot CRT calls
                     * like memcpy inside the JIT — they cost a full x64→EC
                     * round trip as ARM64EC builtins, a large share of the
                     * 57ms menu frame). Result: guest RIP jumped to junk
                     * (0x600000010xx, lr=0xa59696ff...) right after
                     * MSVCP140/VCRUNTIME140 loaded x86_64, before present #1.
                     * So the x86→EC SEH/transition corruption is NOT the
                     * fast-write bug — it's still unfixed, and these
                     * exemptions must stay until it is. */
                    /* Keep vcruntime140.dll as the ARM64EC builtin: its
                     * __C_specific_handler is invoked by Wine's SEH dispatch,
                     * and routing that through FEX corrupts x86 RSP (SEH
                     * dispatcher's exit-thunk arg setup is broken). With the
                     * native arm64ec vcruntime140, Wine calls the handler
                     * directly in ARM64 — no FEX bridging on the exception
                     * path. Other vcruntime/msvcp/concrt DLLs still overlay. */
                    if ([[dll lowercaseString] isEqualToString:@"vcruntime140.dll"]) {
                        vcrtSkipped++;
                        continue;
                    }
                    /* msvcp140.dll: same exemption as vcruntime140, found
                     * 2026-07-03. The MS x86_64 msvcp140 throws a C++
                     * exception during its own DllMain; the x86 throw-record
                     * builder calls RtlPcToFileHeader cross-arch and the
                     * exception-path exit thunk corrupts guest RSP — the
                     * returned module base lands in the return-address slot
                     * and RIP jumps to the MZ header (NoExec loop, no
                     * splash). Keep the ARM64EC builtin so msvcp140's EH
                     * runs natively, like vcruntime140. */
                    if ([[dll lowercaseString] isEqualToString:@"msvcp140.dll"]) {
                        vcrtSkipped++;
                        continue;
                    }
                    NSString *src = [vcrtSource stringByAppendingPathComponent:dll];
                    NSString *dst = [sys32Dir stringByAppendingPathComponent:dll];
                    [fm removeItemAtPath:dst error:nil];
                    if ([fm createSymbolicLinkAtPath:dst withDestinationPath:src error:nil])
                        vcrtLinked++;
                }
                LOG("Symlinked %d MS VC++ Runtime DLLs (x86_64 native) over arm64ec builtins, skipped %d", vcrtLinked, vcrtSkipped);
                dprintf(STDERR_FILENO, "[WineProc] Symlinked %d MS VC++ Runtime DLLs over arm64ec builtins (skipped %d for native EC SEH)\n", vcrtLinked, vcrtSkipped);
            }
        }

        // Build the launch path for Wine's PE loader.
        // If MYTHIC_EXE contains a backslash or starts with a drive letter
        // (e.g. "C:\\Program Files\\Thumper\\THUMPER_win10.exe"), use it
        // as-is. Otherwise treat it as a bare exe name in system32 (legacy
        // path used by cube/fib/hello tests).
        char exe_path[512];
        if (strchr(mythic_exe, '\\') || (mythic_exe[0] && mythic_exe[1] == ':')) {
            snprintf(exe_path, sizeof(exe_path), "%s", mythic_exe);
        } else {
            snprintf(exe_path, sizeof(exe_path), "C:\\windows\\system32\\%s", mythic_exe);
        }

        // Optional MYTHIC_ARGS env var: space-separated args appended to argv.
        // Tokenized in-place; max 16 extra tokens.
        static char args_buf[1024];
        char *extra_argv[16] = {0};
        int extra_argc = 0;
        const char *mythic_args = getenv("MYTHIC_ARGS");
        if (mythic_args && *mythic_args) {
            strncpy(args_buf, mythic_args, sizeof(args_buf) - 1);
            args_buf[sizeof(args_buf) - 1] = 0;
            char *saveptr = NULL;
            for (char *tok = strtok_r(args_buf, " ", &saveptr);
                 tok && extra_argc < 16;
                 tok = strtok_r(NULL, " ", &saveptr)) {
                extra_argv[extra_argc++] = tok;
            }
        }

        char *argv[24];
        int argc = 0;
        argv[argc++] = "wine";
        argv[argc++] = exe_path;
        for (int i = 0; i < extra_argc; i++) argv[argc++] = extra_argv[i];
        argv[argc] = NULL;
        dprintf(STDERR_FILENO, "[WineProc] argv[1] = %s\n", exe_path);
        for (int i = 0; i < extra_argc; i++) {
            dprintf(STDERR_FILENO, "[WineProc] argv[%d] = %s\n", 2 + i, extra_argv[i]);
        }

        /* iOS-Mythic: chdir to the unix path that maps to the exe's Wine
         * directory BEFORE __wine_main. Wine inherits the iOS app sandbox
         * cwd, which becomes a `unix\private\var\mobile\...\Documents\wine\`
         * Wine path — and Thumper's relative cache opens (e.g.,
         * "cache/721e72f7.pc") then resolve to doubled paths that don't
         * exist. Per GPT diagnosis 2026-05-12. Only chdir for full-path EXE
         * launches; bare-name launches (cube, hello-x64) use C:\windows\system32. */
        if (strchr(mythic_exe, '\\') || (mythic_exe[0] && mythic_exe[1] == ':')) {
            /* Convert "C:\Program Files\Thumper\X.exe" → unix path */
            char unix_dir[1024];
            const char *drive_c = "drive_c";
            const char *after_drive = mythic_exe + 3; /* skip "C:\" */
            char *last_sep = strrchr(mythic_exe, '\\');
            if (last_sep && last_sep > mythic_exe + 3) {
                /* Get "Program Files\Thumper" from "C:\Program Files\Thumper\X.exe" */
                size_t dir_len = (size_t)(last_sep - after_drive);
                char windir[512];
                memcpy(windir, after_drive, dir_len);
                windir[dir_len] = 0;
                /* Translate backslashes to forward slashes */
                for (char *p = windir; *p; p++) if (*p == '\\') *p = '/';
                snprintf(unix_dir, sizeof(unix_dir), "%s/%s/%s",
                         g_prefix_path, drive_c, windir);
                int rc = chdir(unix_dir);
                setenv("PWD", unix_dir, 1);
                /* Also set the iOS-specific override so env_ios.c's
                 * get_initial_directory bypasses unix_to_nt_file_name (which
                 * fails to resolve drive_c via dosdevices on iOS). */
                char wine_cwd[768];
                /* Strip trailing exe name from mythic_exe to get the dir part */
                {
                    const char *exe = mythic_exe;
                    size_t dir_len = (size_t)(last_sep - exe);
                    if (dir_len < sizeof(wine_cwd) - 2) {
                        memcpy(wine_cwd, exe, dir_len);
                        wine_cwd[dir_len] = '\\';
                        wine_cwd[dir_len + 1] = 0;
                        setenv("MYTHIC_INITIAL_CWD", wine_cwd, 1);
                    }
                }
                dprintf(STDERR_FILENO, "[WineProc] chdir(%s) = %d errno=%d, PWD + MYTHIC_INITIAL_CWD=%s\n",
                        unix_dir, rc, rc ? errno : 0, wine_cwd);
            }
        }

        // Record this thread so wine_ios_exit knows where to longjmp
        wine_ios_main_thread = pthread_self();
        wine_ios_exit_initialized = 1;

        LOG("Calling __wine_main...");

        if (setjmp(wine_ios_exit_jmpbuf) == 0) {
            __wine_main(argc, argv);
            dprintf(STDERR_FILENO, "[WineProc] __wine_main returned normally\n");
        } else {
            dprintf(STDERR_FILENO, "[WineProc] Wine exited with code %d (caught by longjmp)\n", wine_ios_exit_code);
        }

        g_wine_running = 0;

        // Stop wineserver to prevent CPU spin (iOS kills for excessive CPU)
        dprintf(STDERR_FILENO, "[WineProc] stopping wineserver...\n");
        wineserver_stop();

        dprintf(STDERR_FILENO, "[WineProc] Wine process thread finished cleanly\n");

        // Steam S0: this thread's TEB was mirrored into pthread TSD slot
        // 275 (FEX's hardcoded 0x898) which we don't own via
        // pthread_key_create. Returning from a pthread runs foreign key
        // destructors on whatever's in the slot -> objc_release(TEB)
        // crash wedged the app after every net-test run. Clear it, same
        // as ntdll's pthread_exit_wrapper does for Wine worker threads.
        {
            uintptr_t tsd_base;
            __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base));
            tsd_base &= ~7ULL;
            *(void **)(tsd_base + 275 * 8) = NULL;
        }
    }
    return NULL;
}

int wine_process_start(const char *prefix_path) {
    if (g_wine_running) {
        LOG("Wine process already running");
        return 0;
    }

    if (g_prefix_path) free(g_prefix_path);
    g_prefix_path = strdup(prefix_path);

    LOG("Starting Wine process with prefix: %{public}s", prefix_path);

    g_wine_running = 1;

    // Create socketpair to bypass broken iOS UDS accept()
    // pair[0] = wineserver side (injected as client fd)
    // pair[1] = ntdll side (used as fd_socket)
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
        LOG("socketpair failed: %{public}s", strerror(errno));
        g_wine_running = 0;
        return -1;
    }
    LOG("socketpair created: server_fd=%d, client_fd=%d", pair[0], pair[1]);

    // Set env var for ntdll to pick up instead of server_connect()
    // Must use WINESERVERSOCKET — that's what Wine's server_init_process() checks
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", pair[1]);
    setenv("WINESERVERSOCKET", fd_str, 1);

    // Inject wineserver side — the event loop will pick this up
    wineserver_inject_client_fd(pair[0]);

    // Lower priority so Wine init doesn't starve the main thread
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    struct sched_param sched = { .sched_priority = 20 };  // lower than default (31)
    pthread_attr_setschedparam(&attr, &sched);

    int ret = pthread_create(&g_wine_thread, &attr, wine_process_thread, NULL);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        LOG("Failed to create Wine process thread: %d", ret);
        close(pair[0]);
        close(pair[1]);
        g_wine_running = 0;
        return -1;
    }

    pthread_detach(g_wine_thread);
    LOG("Wine process thread created");
    return 0;
}

int wine_process_is_running(void) {
    return g_wine_running;
}

int mythic_write_continue_flag(void) {
    if (!g_prefix_path) return -1;
    char path[1024];
    snprintf(path, sizeof(path), "%s/drive_c/mythic-continue.flag", g_prefix_path);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG("continue flag write FAILED: %{public}s errno=%d", path, errno);
        return -1;
    }
    close(fd);
    LOG("continue flag written: %{public}s", path);
    return 0;
}
