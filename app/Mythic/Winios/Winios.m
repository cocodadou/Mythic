/* Winios.m — iOS user_driver implementation for Wine.
 *
 * The Wine win32u-unix side declares weak externs `winios_pCreateWindow`,
 * `winios_pProcessEvents`, etc. in build/win32u-unix/driver_ios.c. This
 * file implements them and gets linked into Mythic.app, completing the
 * driver-funcs slots. Slots we don't implement here (e.g. WintabProc,
 * Vulkan) stay weak-resolved-to-NULL and __wine_set_user_driver falls
 * back to win32u's always-success nulldrv_* stubs.
 *
 * Architecture goal: every UIKit-side state lives here, on the Mythic
 * app side; the driver-facing surface is plain C functions taking Wine
 * types (HWND, HCURSOR, etc.) so the win32u side stays portable.
 *
 * Current status: SCAFFOLD. Functions return success/identity values
 * suitable for "first frames render" — full UIKit window/event bridging
 * lands incrementally. Real games will need pProcessEvents to actually
 * drain UIKit events into Wine's queue.
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <ImageIO/ImageIO.h>
#import <QuartzCore/CAMetalLayer.h>
#import <Metal/Metal.h>
#import <os/log.h>
#include <stdarg.h>
#include <pthread.h>

/* Wine-side typedefs we need without pulling in the whole win32u
 * headers (which collide with Apple framework types in Obj-C).
 * BOOL is provided by Foundation; everything else we declare here. */
typedef void *HWND;
typedef void *HCURSOR;
typedef unsigned int UINT;
typedef int  INT;
typedef unsigned long DWORD;
typedef long WINELONG;
typedef struct { WINELONG left, top, right, bottom; } RECT;

/* Wine driver func signatures actually pull more types (window_rects,
 * window_surface) — we forward-declare them as opaque pointers; we
 * never deref them from Obj-C. */
struct window_rects;
struct window_surface;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

static os_log_t winios_log(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.mythic.emulator", "winios.drv"); });
    return log;
}

#define WLOG(fmt, ...) os_log(winios_log(), "[winios] " fmt, ##__VA_ARGS__)

/* ============================================================ *
 * window lifecycle
 * ============================================================ */

BOOL winios_pCreateWindow(HWND hwnd) {
    /* Real impl will set up a UIView with a CAMetalLayer attached to
     * the Mythic window and bind it to this hwnd. For now: success.
     * DXMT-rendered games already get their CAMetalLayer via the
     * IOSDisplayShim macdrv_functions path — no need to allocate one
     * per HWND yet. */
    WLOG("pCreateWindow hwnd=%p", hwnd);
    return TRUE;
}

static void winios_remove_layer(HWND hwnd);   /* compositor, below */

void winios_pDestroyWindow(HWND hwnd) {
    WLOG("pDestroyWindow hwnd=%p", hwnd);
    winios_remove_layer(hwnd);
}

UINT winios_pShowWindow(HWND hwnd, INT cmd, RECT *rect, UINT swp) {
    /* Returning 0 means "we didn't override the swp flags — let Wine
     * use its default behavior." Plus the rect already came from
     * win32u's calculations. No-op for now. */
    return 0;
}

void winios_pWindowPosChanged(HWND hwnd, HWND insert_after, HWND owner_hint, UINT swp_flags,
                              const struct window_rects *new_rects, struct window_surface *surface) {
    /* Real impl will resize the UIView/CAMetalLayer to match. No-op
     * for now — DXMT's swapchain owns its own dimensions explicitly. */
}

/* ============================================================ *
 * event pump — touch → mouse bridge
 * ============================================================
 *
 * Ring buffer of pending touch events posted by the Mythic Swift UI
 * (via winios_post_touch / winios_post_touch_move / winios_post_touch_up).
 * The Wine thread drains it from pProcessEvents, translating each
 * touch event into a synthesized hardware mouse INPUT and dispatching
 * via NtUserSendHardwareInput (through the winios_drv_post_mouse C
 * bridge in driver_ios.c). */

/* Mouse-event flags from <winuser.h> that we emit. We don't include
 * winuser.h to avoid header soup with UIKit, so reproduce constants. */
#define MOUSEEVENTF_MOVE        0x0001
#define MOUSEEVENTF_LEFTDOWN    0x0002
#define MOUSEEVENTF_LEFTUP      0x0004
#define MOUSEEVENTF_RIGHTDOWN   0x0008
#define MOUSEEVENTF_RIGHTUP     0x0010
#define MOUSEEVENTF_WHEEL       0x0800
#define MOUSEEVENTF_ABSOLUTE    0x8000

extern void winios_drv_post_mouse(int x, int y, unsigned int flags, unsigned int mouse_data, void *hwnd);
extern void winios_drv_post_key(unsigned short vk, unsigned int flags);
extern void winios_dump_window_tree(void);
extern void ios_dump_all_thread_stacks(void);

#define WINIOS_RING_SIZE 256
#define WINIOS_EV_MOUSE 0
#define WINIOS_EV_KEY   1
#define KEYEVENTF_KEYUP 0x0002
typedef struct {
    unsigned int type;       /* WINIOS_EV_MOUSE / WINIOS_EV_KEY */
    int x, y;                /* mouse: coords; key: x = virtual-key code */
    unsigned int flags;      /* mouse: MOUSEEVENTF_*; key: KEYEVENTF_* */
    unsigned int data;       /* mouse: mouseData (wheel delta) */
} winios_input_event_t;

static struct {
    winios_input_event_t buf[WINIOS_RING_SIZE];
    unsigned int head;       /* producer cursor (Swift side) */
    unsigned int tail;       /* consumer cursor (Wine drain) */
    pthread_mutex_t lock;
} g_input_q = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void winios_q_push_ev(unsigned int type, int x, int y, unsigned int flags, unsigned int data) {
    pthread_mutex_lock(&g_input_q.lock);
    unsigned int next = (g_input_q.head + 1) % WINIOS_RING_SIZE;
    if (next != g_input_q.tail) {
        g_input_q.buf[g_input_q.head] = (winios_input_event_t){type, x, y, flags, data};
        g_input_q.head = next;
    }
    /* If buffer is full we drop the oldest event by simply not advancing —
     * better than blocking the UI thread on a Wine event drain. */
    pthread_mutex_unlock(&g_input_q.lock);
}

/* Public C entry points for Swift / UIKit gesture handlers.
 * Coordinates are in iOS view-local pixels; we scale to a fixed
 * 1024×768 logical surface inside winios_pProcessEvents to match
 * what DXMT swapchains use. */
void winios_post_touch_down(int x, int y) {
    fprintf(stderr, "[winios] post_touch_down x=%d y=%d\n", x, y); fflush(stderr);
    winios_q_push_ev(WINIOS_EV_MOUSE, x, y, MOUSEEVENTF_MOVE | MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE, 0);
}

void winios_post_touch_move(int x, int y) {
    static unsigned cnt;
    if ((cnt++ % 30) == 0) {
        fprintf(stderr, "[winios] post_touch_move x=%d y=%d (n=%u)\n", x, y, cnt); fflush(stderr);
    }
    winios_q_push_ev(WINIOS_EV_MOUSE, x, y, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, 0);
}

void winios_post_touch_up(int x, int y) {
    fprintf(stderr, "[winios] post_touch_up x=%d y=%d\n", x, y); fflush(stderr);
    winios_q_push_ev(WINIOS_EV_MOUSE, x, y, MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE, 0);
}

/* Key press bridge. vk = Windows virtual-key code, down = 1 for press,
 * 0 for release. Queued like mouse events; drained in pProcessEvents. */
void winios_post_key(int vk, int down) {
    fprintf(stderr, "[winios] post_key vk=0x%x down=%d\n", vk, down); fflush(stderr);
    winios_q_push_ev(WINIOS_EV_KEY, vk, 0, down ? 0 : KEYEVENTF_KEYUP, 0);
}

BOOL winios_pProcessEvents(DWORD mask) {
    static unsigned int cnt;
    static int quiet = -1;
    if (quiet < 0) quiet = getenv("MYTHIC_QUIET") != NULL;
    if ((cnt++ % 240) == 0 && !quiet) {
        fprintf(stderr, "[winios] pProcessEvents called n=%u\n", cnt); fflush(stderr);
    }
    /* Desktop debugging: dump the full window tree every ~5s. Runs on
     * this wine thread (valid TEB — the dump walks win32u internals). */
    static int desk = -1;
    if (desk < 0) desk = ({ const char *d = getenv("MYTHIC_DESKTOP"); d && *d == '1'; });
    if (desk) {
        static double next_tree_dump;
        double now = CACurrentMediaTime();
        if (now >= next_tree_dump) {
            next_tree_dump = now + 5.0;
            winios_dump_window_tree();
        }
    }
    BOOL drained = FALSE;
    for (;;) {
        winios_input_event_t e;
        pthread_mutex_lock(&g_input_q.lock);
        if (g_input_q.tail == g_input_q.head) {
            pthread_mutex_unlock(&g_input_q.lock);
            break;
        }
        e = g_input_q.buf[g_input_q.tail];
        g_input_q.tail = (g_input_q.tail + 1) % WINIOS_RING_SIZE;
        pthread_mutex_unlock(&g_input_q.lock);

        fprintf(stderr, "[winios] drain type=%u x=%d y=%d flags=0x%x\n", e.type, e.x, e.y, e.flags); fflush(stderr);
        if (e.type == WINIOS_EV_KEY)
            winios_drv_post_key((unsigned short)e.x, e.flags);
        else
            winios_drv_post_mouse(e.x, e.y, e.flags, e.data, NULL);
        drained = TRUE;
    }
    return drained;
}

/* ============================================================ *
 * S2 compositor: window surfaces → CALayers
 * ============================================================
 *
 * The win32u side (driver_ios.c winios_surface_flush) calls
 * winios_surface_present with a window's full 32bpp BGRX DIB after
 * every GDI flush, and winios_window_frame with the window's visible
 * rect (desktop pixel coords) on every position change. We keep one
 * CALayer per HWND inside a full-screen, touch-transparent UIView and
 * let Core Animation do the compositing. Desktop coords are native
 * pixels (e.g. 1170x2532); layers are placed in points (÷ screen
 * scale). Only active when MYTHIC_DESKTOP=1 (the driver side gates
 * surface creation, so games never reach these). */

static NSMutableDictionary<NSNumber *, CALayer *> *g_layers;
static NSMutableDictionary<NSNumber *, NSValue *> *g_px_rects;  /* hwnd → last px rect */
static NSMutableDictionary<NSNumber *, NSValue *> *g_surf_sizes; /* hwnd → surface px size */
static NSMutableDictionary<NSNumber *, CAMetalLayer *> *g_metal_layers; /* hwnd → DXMT layer */
static NSMutableDictionary<NSNumber *, NSValue *> *g_client_rects;      /* hwnd → client px rect */
static void winios_place_metal_layer(NSNumber *key);

/* Surfaces are 128px-aligned (win32u), usually LARGER than the window.
 * Crop the layer contents to the window's actual size or everything
 * stretches/squashes. Main thread only. */
static void winios_apply_contents_rect(NSNumber *key, CALayer *l) {
    NSValue *sv = g_surf_sizes[key], *rv = g_px_rects[key];
    if (!sv || !rv) return;
    CGSize surf = sv.CGSizeValue;
    CGRect px = rv.CGRectValue;
    if (surf.width <= 0 || surf.height <= 0 || CGRectIsEmpty(px)) return;
    l.contentsRect = CGRectMake(0, 0,
                                MIN(px.size.width / surf.width, 1.0),
                                MIN(px.size.height / surf.height, 1.0));
}
static UIView *g_compositor_view;
static CALayer *g_desk_bg;               /* teal desktop-area backdrop */
static CGFloat g_px_to_pt = 1.0 / 3.0;   /* desktop px → screen pt */
static CGPoint g_desk_origin;            /* desktop (0,0) in view pt (letterbox offset) */
static CGRect g_comp_frame;              /* presentation area (window coords), from Swift */
static BOOL g_comp_frame_set;

static CGRect winios_layer_rect(int x, int y, int w, int h) {
    CGFloat s = g_px_to_pt;
    return CGRectMake(g_desk_origin.x + x * s, g_desk_origin.y + y * s, w * s, h * s);
}

/* main thread only. Sizes the compositor to the presentation frame and
 * aspect-fits the wine desktop inside it; repositions existing layers. */
static void winios_layout_compositor(void) {
    if (!g_compositor_view) return;
    UIWindow *win = g_compositor_view.superview ? (UIWindow *)g_compositor_view.superview : nil;
    CGRect frame = g_comp_frame_set ? g_comp_frame : (win ? win.bounds : g_compositor_view.frame);
    g_compositor_view.frame = frame;

    const char *dw = getenv("MYTHIC_SCREEN_W"), *dh = getenv("MYTHIC_SCREEN_H");
    int desk_w = dw ? atoi(dw) : 1024, desk_h = dh ? atoi(dh) : 768;
    if (desk_w <= 0) desk_w = 1024;
    if (desk_h <= 0) desk_h = 768;
    CGFloat s = MIN(frame.size.width / desk_w, frame.size.height / desk_h);
    CGSize fit = CGSizeMake(desk_w * s, desk_h * s);
    g_px_to_pt = s;
    g_desk_origin = CGPointMake((frame.size.width - fit.width) / 2,
                                (frame.size.height - fit.height) / 2);
    g_desk_bg.frame = CGRectMake(g_desk_origin.x, g_desk_origin.y, fit.width, fit.height);

    /* re-place existing window layers under the new mapping */
    for (NSNumber *key in g_px_rects) {
        CALayer *l = g_layers[key];
        CGRect r = g_px_rects[key].CGRectValue;
        if (l) l.frame = winios_layer_rect((int)r.origin.x, (int)r.origin.y,
                                           (int)r.size.width, (int)r.size.height);
        winios_place_metal_layer(key);
    }
    fprintf(stderr, "[winios] compositor layout: frame=(%.0f,%.0f %.0fx%.0f) desk=%dx%d px_to_pt=%.3f\n",
            frame.origin.x, frame.origin.y, frame.size.width, frame.size.height,
            desk_w, desk_h, (double)g_px_to_pt);
    fflush(stderr);
}

/* Called from Swift (MetalBackedView) with the presentation area in
 * window coordinates — same geometry contract as the Metal host view. */
void winios_set_compositor_frame(double x, double y, double w, double h) {
    dispatch_async(dispatch_get_main_queue(), ^{
        CGRect f = CGRectMake(x, y, w, h);
        /* layoutSubviews storms identical frames — skip no-op relayouts */
        if (g_comp_frame_set && CGRectEqualToRect(g_comp_frame, f)) return;
        g_comp_frame = f;
        g_comp_frame_set = YES;
        winios_layout_compositor();
    });
}

/* main thread only */
static void winios_ensure_compositor(void) {
    if (g_compositor_view) return;
    /* desktop mode only — games render via DXMT's Metal layer and the
     * compositor backdrop would cover it (2026-07-06 Thumper regression) */
    const char *dm = getenv("MYTHIC_DESKTOP");
    if (!dm || *dm != '1') return;
    UIWindow *win = nil;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w.isKeyWindow) { win = w; break; }
    }
    if (!win) win = UIApplication.sharedApplication.windows.firstObject;
    if (!win) return;
    g_layers = [NSMutableDictionary new];
    g_px_rects = [NSMutableDictionary new];
    g_surf_sizes = [NSMutableDictionary new];
    g_compositor_view = [[UIView alloc] initWithFrame:win.bounds];
    g_compositor_view.userInteractionEnabled = NO;  /* touches fall through */
    g_compositor_view.clipsToBounds = YES;
    /* letterbox area: near-black; desktop area: classic teal (until
     * explorer's own background paint works) */
    g_compositor_view.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1.0];
    g_desk_bg = [CALayer layer];
    g_desk_bg.backgroundColor = [UIColor colorWithRed:0.0 green:0.502 blue:0.502 alpha:1.0].CGColor;
    [g_compositor_view.layer addSublayer:g_desk_bg];
    [win addSubview:g_compositor_view];
    winios_layout_compositor();
    fprintf(stderr, "[winios] compositor attached inside presentation frame\n");
    fflush(stderr);
    /* Wedged-thread triage: sample every thread's stack every 20s from
     * an app-side timer — keeps firing even when all wine threads are
     * stuck (unlike the tree dump, which rides wine's event drain). */
    static dispatch_source_t stack_timer;
    if (!stack_timer) {
        stack_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                          dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
        dispatch_source_set_timer(stack_timer, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC),
                                  20 * NSEC_PER_SEC, NSEC_PER_SEC);
        dispatch_source_set_event_handler(stack_timer, ^{ ios_dump_all_thread_stacks(); });
        dispatch_resume(stack_timer);
    }
}

/* main thread only */
static CALayer *winios_layer_for(HWND hwnd, bool create) {
    NSNumber *key = @((uintptr_t)hwnd);
    CALayer *l = g_layers[key];
    if (!l && create) {
        l = [CALayer layer];
        l.anchorPoint = CGPointMake(0, 0);
        l.magnificationFilter = kCAFilterNearest;
        l.opaque = YES;
        [g_compositor_view.layer addSublayer:l];
        g_layers[key] = l;
        fprintf(stderr, "[winios] layer created for hwnd=%p (%lu layers)\n",
                hwnd, (unsigned long)g_layers.count);
        fflush(stderr);
    }
    return l;
}

static void winios_remove_layer(HWND hwnd) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!g_layers) return;
        NSNumber *key = @((uintptr_t)hwnd);
        CALayer *l = g_layers[key];
        if (l) {
            [l removeFromSuperlayer];
            [g_layers removeObjectForKey:key];
            [g_px_rects removeObjectForKey:key];
        }
        CAMetalLayer *ml = g_metal_layers[key];
        if (ml) {
            [ml removeFromSuperlayer];
            [g_metal_layers removeObjectForKey:key];
            [g_client_rects removeObjectForKey:key];
            fprintf(stderr, "[winios] metal layer removed for hwnd=%p\n", hwnd);
            fflush(stderr);
        }
    });
}

/* ============================================================ *
 * S2-7: DXMT presentation into desktop windows
 * ============================================================
 *
 * In desktop mode a D3D11 app's swapchain gets a CAMetalLayer that is a
 * SUBLAYER of its window's compositor CALayer, framed to the window's
 * CLIENT rect. Sublayers render above the layer's own contents (the GDI
 * DIB), so the title bar / borders stay visible around the game while
 * the client area shows DXMT output. Core Animation composites the rest.
 * Game (non-desktop) mode keeps the fullscreen singleton layer via
 * IOSDisplayShim — none of this runs. */

/* main thread only — frame the metal sublayer to the client rect in the
 * parent (window) layer's coordinate space. Parent bounds are the window
 * rect in points, so client offset = (client_px - window_px) * scale. */
static void winios_place_metal_layer(NSNumber *key) {
    CAMetalLayer *ml = g_metal_layers[key];
    if (!ml) return;
    NSValue *wv = g_px_rects[key], *cv = g_client_rects[key];
    if (!wv || !cv) return;
    CGRect w = wv.CGRectValue, c = cv.CGRectValue;
    CGFloat s = g_px_to_pt;
    ml.frame = CGRectMake((c.origin.x - w.origin.x) * s,
                          (c.origin.y - w.origin.y) * s,
                          c.size.width * s, c.size.height * s);
}

/* Called by IOSDisplayShim on a wine thread when DXMT creates a swapchain
 * view for an HWND in desktop mode. Returns the (unretained) CAMetalLayer;
 * the shim CFRetains it for DXMT's lifetime handling. */
CAMetalLayer *winios_metal_layer_for_hwnd(void *hwnd) {
    __block CAMetalLayer *result = nil;
    void (^make)(void) = ^{
        winios_ensure_compositor();
        if (!g_compositor_view) return;
        if (!g_metal_layers) g_metal_layers = [NSMutableDictionary new];
        NSNumber *key = @((uintptr_t)hwnd);
        CAMetalLayer *ml = g_metal_layers[key];
        if (!ml) {
            CALayer *win = winios_layer_for(hwnd, true);
            ml = [CAMetalLayer layer];
            ml.anchorPoint = CGPointMake(0, 0);
            ml.device = MTLCreateSystemDefaultDevice();
            ml.pixelFormat = MTLPixelFormatBGRA8Unorm;
            ml.opaque = YES;
            g_metal_layers[key] = ml;
            [win addSublayer:ml];
            winios_place_metal_layer(key);
            if (CGRectIsEmpty(ml.frame) && !CGRectIsEmpty(win.bounds))
                ml.frame = win.bounds;   /* client rect not delivered yet */
            fprintf(stderr, "[winios] metal layer created for hwnd=%p frame=(%.0f,%.0f %.0fx%.0f)\n",
                    hwnd, ml.frame.origin.x, ml.frame.origin.y,
                    ml.frame.size.width, ml.frame.size.height);
            fflush(stderr);
        }
        result = ml;
    };
    if ([NSThread isMainThread]) make();
    else dispatch_sync(dispatch_get_main_queue(), make);
    return result;
}

/* Called from win32u's pWindowPosChanged wrapper (wine thread).
 * x/y/w/h = visible rect, cx/cy/cw/ch = client rect, desktop pixels. */
void winios_window_frame(HWND hwnd, int x, int y, int w, int h, int visible,
                         int cx, int cy, int cw, int ch) {
    dispatch_async(dispatch_get_main_queue(), ^{
        winios_ensure_compositor();
        if (!g_compositor_view) return;
        CALayer *l = winios_layer_for(hwnd, true);
        NSNumber *key = @((uintptr_t)hwnd);
        g_px_rects[key] = [NSValue valueWithCGRect:CGRectMake(x, y, w, h)];
        if (!g_client_rects) g_client_rects = [NSMutableDictionary new];
        g_client_rects[key] = [NSValue valueWithCGRect:CGRectMake(cx, cy, cw, ch)];
        [CATransaction begin];
        [CATransaction setDisableActions:YES];
        l.frame = winios_layer_rect(x, y, w, h);
        l.hidden = !visible;
        winios_apply_contents_rect(key, l);
        winios_place_metal_layer(key);
        [CATransaction commit];
    });
}

/* MYTHIC_DUMP_SURFACES=1: save each window's DIB as PNG under
 * Documents/surfdump/ — surf-<hwnd>-first.png once, then
 * surf-<hwnd>-latest.png at most every 2s. Ground truth for whether a
 * rendering bug is in the surface bits (wine paint path) or in the
 * compositor (crop/scale). */
static void winios_dump_surface_png(HWND hwnd, NSData *data, int sw, int sh, int stride) {
    static dispatch_queue_t q;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ q = dispatch_queue_create("winios.surfdump", DISPATCH_QUEUE_SERIAL); });
    dispatch_async(q, ^{
        static NSMutableDictionary<NSNumber *, NSNumber *> *lastWrite;
        static NSMutableSet<NSNumber *> *wroteFirst;
        if (!lastWrite) { lastWrite = [NSMutableDictionary new]; wroteFirst = [NSMutableSet new]; }
        NSNumber *key = @((uintptr_t)hwnd);
        double now = CACurrentMediaTime();
        BOOL first = ![wroteFirst containsObject:key];
        NSNumber *lw = lastWrite[key];
        if (!first && lw && now - lw.doubleValue < 2.0) return;
        lastWrite[key] = @(now);
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *dir = [docs stringByAppendingPathComponent:@"surfdump"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGDataProviderRef dp = CGDataProviderCreateWithCFData((__bridge CFDataRef)data);
        CGImageRef img = CGImageCreate(sw, sh, 8, 32, stride, cs,
                                       kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst,
                                       dp, NULL, false, kCGRenderingIntentDefault);
        if (img) {
            NSString *name = [NSString stringWithFormat:@"surf-%p-%s.png", hwnd, first ? "first" : "latest"];
            NSURL *url = [NSURL fileURLWithPath:[dir stringByAppendingPathComponent:name]];
            CGImageDestinationRef dest = CGImageDestinationCreateWithURL((__bridge CFURLRef)url, CFSTR("public.png"), 1, NULL);
            if (dest) {
                CGImageDestinationAddImage(dest, img, NULL);
                if (CGImageDestinationFinalize(dest) && first) {
                    [wroteFirst addObject:key];
                    fprintf(stderr, "[winios] surfdump wrote %s (%dx%d)\n", name.UTF8String, sw, sh);
                    fflush(stderr);
                }
                CFRelease(dest);
            }
            CGImageRelease(img);
        }
        CGDataProviderRelease(dp);
        CGColorSpaceRelease(cs);
    });
}

/* Called from winios_surface_flush (wine thread) with the surface's
 * whole DIB. Copy immediately — `bits` is only valid for this call. */
void winios_surface_present(HWND hwnd, int dx, int dy, int dw, int dh,
                            int sw, int sh, int stride, const void *bits) {
    if (sw <= 0 || sh <= 0 || !bits) return;
    NSData *data = [NSData dataWithBytes:bits length:(size_t)stride * sh];
    static int dumpSurf = -1;
    if (dumpSurf < 0) dumpSurf = getenv("MYTHIC_DUMP_SURFACES") != NULL;
    if (dumpSurf) winios_dump_surface_png(hwnd, data, sw, sh, stride);
    static unsigned cnt;
    /* ml371: was capped at 12 total, which made present LIVENESS
     * unobservable — a 30-min run's log showed nothing after minute 2 and
     * read exactly like a frozen present path. First 12, then every 200th
     * with the running count so silence means silence. */
    cnt++;
    if (cnt <= 12 || (cnt % 200) == 0) {
        fprintf(stderr, "[winios] present #%u hwnd=%p dirty=(%d,%d %dx%d) surf=%dx%d\n",
                cnt, hwnd, dx, dy, dw, dh, sw, sh);
        fflush(stderr);
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        winios_ensure_compositor();
        if (!g_compositor_view) return;
        CALayer *l = winios_layer_for(hwnd, true);
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGDataProviderRef dp = CGDataProviderCreateWithCFData((__bridge CFDataRef)data);
        /* GDI 32bpp DIB = BGRX little-endian, no alpha */
        CGImageRef img = CGImageCreate(sw, sh, 8, 32, stride, cs,
                                       kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst,
                                       dp, NULL, false, kCGRenderingIntentDefault);
        if (img) {
            NSNumber *key = @((uintptr_t)hwnd);
            l.contents = (__bridge id)img;
            g_surf_sizes[key] = [NSValue valueWithCGSize:CGSizeMake(sw, sh)];
            if (CGRectIsEmpty(l.frame)) {
                /* frame not delivered yet — place at surface size */
                g_px_rects[key] = [NSValue valueWithCGRect:CGRectMake(0, 0, sw, sh)];
                l.frame = winios_layer_rect(0, 0, sw, sh);
            }
            winios_apply_contents_rect(key, l);
            CGImageRelease(img);
        }
        CGDataProviderRelease(dp);
        CGColorSpaceRelease(cs);
    });
}

/* ============================================================ *
 * S2 trackpad pointer + rendered cursor
 * ============================================================ */

static CALayer *g_cursor_layer;

static UIImage *winios_cursor_image(void) {
    static UIImage *img;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        CGSize sz = CGSizeMake(14, 21);
        UIGraphicsImageRenderer *r = [[UIGraphicsImageRenderer alloc] initWithSize:sz];
        img = [r imageWithActions:^(UIGraphicsImageRendererContext *ctx __unused) {
            /* classic arrow: white fill, black outline */
            UIBezierPath *p = [UIBezierPath bezierPath];
            [p moveToPoint:CGPointMake(0.5, 0.5)];
            [p addLineToPoint:CGPointMake(0.5, 15.5)];
            [p addLineToPoint:CGPointMake(4.2, 12.2)];
            [p addLineToPoint:CGPointMake(7.0, 19.0)];
            [p addLineToPoint:CGPointMake(9.6, 17.8)];
            [p addLineToPoint:CGPointMake(6.8, 11.1)];
            [p addLineToPoint:CGPointMake(11.8, 10.7)];
            [p closePath];
            [[UIColor whiteColor] setFill];
            [p fill];
            [[UIColor blackColor] setStroke];
            p.lineWidth = 1.0;
            [p stroke];
        }];
    });
    return img;
}

/* Wine cursor image state (px). w==0 → builtin arrow fallback. */
static int g_cur_w, g_cur_h, g_cur_hx, g_cur_hy;
static CGPoint g_cursor_pos_px;

/* main thread only */
static void winios_ensure_cursor_layer(void) {
    if (g_cursor_layer || !g_compositor_view) return;
    UIImage *img = winios_cursor_image();
    g_cursor_layer = [CALayer layer];
    g_cursor_layer.zPosition = 10000;   /* above every window layer */
    g_cursor_layer.anchorPoint = CGPointMake(0, 0);
    g_cursor_layer.contents = (id)img.CGImage;
    g_cursor_layer.bounds = CGRectMake(0, 0, img.size.width, img.size.height);
    g_cursor_layer.magnificationFilter = kCAFilterNearest;
    [g_compositor_view.layer addSublayer:g_cursor_layer];
}

/* main thread only — place (and size) the cursor at its stored px pos,
 * honoring the wine cursor's hotspot when one is set */
static void winios_cursor_place(void) {
    if (!g_cursor_layer) return;
    CGFloat x = g_cursor_pos_px.x, y = g_cursor_pos_px.y;
    if (g_cur_w > 0) {
        g_cursor_layer.bounds = CGRectMake(0, 0, g_cur_w * g_px_to_pt, g_cur_h * g_px_to_pt);
        g_cursor_layer.position = CGPointMake(g_desk_origin.x + (x - g_cur_hx) * g_px_to_pt,
                                              g_desk_origin.y + (y - g_cur_hy) * g_px_to_pt);
    } else {
        g_cursor_layer.position = CGPointMake(g_desk_origin.x + x * g_px_to_pt,
                                              g_desk_origin.y + y * g_px_to_pt);
    }
}

void winios_cursor_move(int x, int y) {
    dispatch_async(dispatch_get_main_queue(), ^{
        winios_ensure_compositor();
        if (!g_compositor_view) return;
        winios_ensure_cursor_layer();
        g_cursor_pos_px = CGPointMake(x, y);
        [CATransaction begin];
        [CATransaction setDisableActions:YES];
        winios_cursor_place();
        [CATransaction commit];
    });
}

/* Called from winios_drv_set_cursor (wine thread) with a straight-alpha
 * BGRA image + hotspot whenever the wine cursor changes (arrow → I-beam
 * → resize arrows → app cursors). Copy before returning. */
void winios_cursor_set(unsigned int cur_id, int w, int h, int hot_x, int hot_y, const void *bgra) {
    if (w <= 0 || h <= 0 || !bgra) return;
    NSData *data = [NSData dataWithBytes:bgra length:(size_t)w * h * 4];
    dispatch_async(dispatch_get_main_queue(), ^{
        winios_ensure_compositor();
        if (!g_compositor_view) return;
        winios_ensure_cursor_layer();
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGDataProviderRef dp = CGDataProviderCreateWithCFData((__bridge CFDataRef)data);
        CGImageRef img = CGImageCreate(w, h, 8, 32, w * 4, cs,
                                       kCGBitmapByteOrder32Little | kCGImageAlphaFirst,
                                       dp, NULL, false, kCGRenderingIntentDefault);
        if (img) {
            [CATransaction begin];
            [CATransaction setDisableActions:YES];
            g_cursor_layer.contents = (__bridge id)img;
            g_cur_w = w; g_cur_h = h; g_cur_hx = hot_x; g_cur_hy = hot_y;
            winios_cursor_place();
            [CATransaction commit];
            CGImageRelease(img);
        }
        CGDataProviderRelease(dp);
        CGColorSpaceRelease(cs);
    });
}

void winios_cursor_show(int show) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_cursor_layer) g_cursor_layer.hidden = !show;
    });
}

/* Swift trackpad engine → wine. Absolute desktop-pixel coords; the
 * engine owns the cursor position. */
void winios_pointer(int x, int y, unsigned int flags, unsigned int data) {
    winios_q_push_ev(WINIOS_EV_MOUSE, x, y, flags, data);
    if (flags & MOUSEEVENTF_MOVE) winios_cursor_move(x, y);
}

/* ============================================================ *
 * cursor (no cursor on iOS — these are no-ops)
 * ============================================================ */

void winios_pSetCursor(HWND hwnd, HCURSOR cursor) {
    /* iOS has no mouse cursor. Games that hide/show the cursor for
     * mouselook etc. just get nothing — fine for touch-driven input. */
}

void winios_pDestroyCursorIcon(HCURSOR cursor) {
    /* nothing to release; we never allocated anything for the cursor */
}
