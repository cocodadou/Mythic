import SwiftUI
import UIKit
import QuartzCore
import Metal
import os.log

// 2026-07-03 window-hosted Metal layer.
//
// The presenting CAMetalLayer must NOT be a SwiftUI-hosted view's backing
// layer: on iOS 26/27, SwiftUI's hosting intermittently routes such layers
// through an indirect/snapshot path where direct Metal presentations are
// silently dropped — presented drawables complete with presentedTime==0
// (measured), the screen freezes on stale content, and only full-tree
// re-renders (screenshots) reveal new frames. Which path a given run gets
// appeared random — the "sometimes rendering starts at present #9,
// sometimes never" lottery.
//
// So the layer now lives in MetalHostView, a raw UIView added directly to
// the UIWindow (classic game setup, no SwiftUI management). The SwiftUI-
// hosted MetalBackedView remains as a transparent layout placeholder that
// tracks geometry and handles touch input. The host view sits on top of
// the window but has interaction disabled, so touches fall through to the
// SwiftUI hierarchy (and thus to the placeholder's touch handlers).

/// Raw window-level host for the presenting CAMetalLayer.
final class MetalHostView: UIView {
    // Process-lifetime singleton. The CAMetalLayer is registered with DXMT's
    // swapchain exactly once; if the host were recreated on view teardown
    // (rotation, re-attach) DXMT would keep presenting to the DEAD layer —
    // black surface both ways (2026-07-05 landscape regression). One host,
    // one layer, forever; only its FRAME is re-parented/resized.
    static let shared = MetalHostView(frame: CGRect(x: 0, y: 0, width: 800, height: 600))

    override class var layerClass: AnyClass { return CAMetalLayer.self }
    var metalLayer: CAMetalLayer { return layer as! CAMetalLayer }
    override init(frame: CGRect) {
        super.init(frame: frame)
        isUserInteractionEnabled = false   // touches fall through to SwiftUI
        backgroundColor = .black
        contentScaleFactor = UIScreen.main.scale
        metalLayer.device = MTLCreateSystemDefaultDevice()
        metalLayer.pixelFormat = .bgra8Unorm
        metalLayer.framebufferOnly = true
        // 2026-07-03 MeloNX trick: displaySyncEnabled is macOS-public but
        // exists as PRIVATE API on iOS. Disabling it takes our presents out
        // of the display-sync scheduling machinery — the thing that has been
        // silently dropping them (presentedTime==0 on all but occasional
        // frames) at our sub-1Hz game present cadence. MeloNX (shipping
        // Switch emulator) sets exactly this pair on its layer.
        let syncSel = NSSelectorFromString("setDisplaySyncEnabled:")
        if metalLayer.responds(to: syncSel) {
            metalLayer.perform(syncSel, with: NSNumber(value: false))
            LogStore.shared.log("MetalLayer: displaySyncEnabled=false (private API, MeloNX pattern)")
        }
        let fpsSel = NSSelectorFromString("setNominalFramesPerSecond:")
        if metalLayer.responds(to: fpsSel) {
            metalLayer.perform(fpsSel, with: 60 as NSNumber)
        }
        UIApplication.shared.isIdleTimerDisabled = true
        // Set once so DXMT's swapchain setup never blocks on a zero-sized
        // layer. After this, DXMT's setProps is the ONLY drawableSize
        // writer — per-layout rewrites from the app were a second writer
        // fighting it (pool churn on every SwiftUI layout pass).
        metalLayer.drawableSize = CGSize(width: 800, height: 600)
    }
    required init?(coder: NSCoder) { fatalError() }
}

// SwiftUI-hosted placeholder: geometry + touch input only.
final class MetalBackedView: UIView {
    private static var layerRegistered = false

    // Hardware keyboard bridge: the view becomes first responder so the iOS
    // software keyboard appears, and each typed character is forwarded to
    // Wine as a virtual-key sequence (winios_post_key → send_hardware_message
    // → WM_KEYDOWN/WM_CHAR). Lets the user type into Windows dialogs (e.g.
    // Run) directly instead of relying on the browse list.
    static weak var keyboardTarget: MetalBackedView?
    override var canBecomeFirstResponder: Bool { true }
    static func toggleKeyboard() {
        guard let v = keyboardTarget else { return }
        if v.isFirstResponder { v.resignFirstResponder() }
        else { v.becomeFirstResponder() }
    }

    override init(frame: CGRect) {
        super.init(frame: frame)
        // Multi-touch REQUIRED: with it off, a fast double-tap's second
        // touch (landing before the first lift is processed) is silently
        // swallowed — drag-arm never fired (2026-07-06). Two-finger
        // scroll/right-click need it too.
        self.isMultipleTouchEnabled = true
        self.isUserInteractionEnabled = true
        self.backgroundColor = .clear
    }
    required init?(coder: NSCoder) { super.init(coder: coder) }

    // Visibility-stall postmortem (2026-07-03): the intermittent "presents
    // count but the screen stays black until a bg/fg or screenshot" state
    // was probed exhaustively — drawable leaks, present pacing, panel idle,
    // SwiftUI hosting, display-sync, CADisplayLink, transaction nudges and
    // view re-attach kicks were all eliminated (none changed it; only true
    // scene-level lifecycle events land pending frames, ~1-2 each). The one
    // robust correlate is present cadence: 60 FPS content always displays,
    // ~1 FPS content mostly doesn't. Resolution path: raise game FPS (perf
    // work), with a steady-rate re-present in DXMT as fallback insurance.

    /// Largest 4:3 rect (the 1024×768 logical surface's aspect) that fits
    /// centered in our bounds. The window-level host view gets THIS frame,
    /// not our full bounds — otherwise landscape stretches the game to the
    /// display edges (2026-07-05). Touch mapping uses the same rect so
    /// letterboxing never skews input.
    private func gameRect() -> CGRect {
        let gw: CGFloat = 1024, gh: CGFloat = 768
        let scale = min(bounds.width / gw, bounds.height / gh)
        let w = gw * scale, h = gh * scale
        return CGRect(x: (bounds.width - w) / 2, y: (bounds.height - h) / 2,
                      width: max(w, 1), height: max(h, 1))
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        guard let w = window else { return }   // detach: leave the host be
        MetalBackedView.keyboardTarget = self  // keyboard button targets the live view
        // SwiftUI ancestors attach gesture recognizers that can delay or
        // cancel raw touch delivery (double-tap timing is exactly what
        // they punish). Defuse them for our subtree.
        var v: UIView? = self
        while let s = v {
            s.gestureRecognizers?.forEach {
                $0.cancelsTouchesInView = false
                $0.delaysTouchesBegan = false
                $0.delaysTouchesEnded = false
            }
            v = s.superview
        }
        let host = MetalHostView.shared
        if host.superview !== w {
            host.removeFromSuperview()
            w.addSubview(host)
        }
        host.frame = convert(gameRect(), to: w)
        // S2 desktop mode: the winios compositor renders the wine virtual
        // desktop aspect-fit inside THIS placeholder's area, exactly like
        // the games' Metal layer — never over the whole phone screen.
        let full = convert(bounds, to: w)
        winios_set_compositor_frame(full.minX, full.minY, full.width, full.height)
        if !Self.layerRegistered {
            Self.layerRegistered = true
            mythic_display_set_layer(host.metalLayer)
            LogStore.shared.log("MetalLayer registered with DXMT shim (window-hosted singleton)", level: .success)
        }
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        if let w = window {
            MetalHostView.shared.frame = convert(gameRect(), to: w)
            let full = convert(bounds, to: w)
            winios_set_compositor_frame(full.minX, full.minY, full.width, full.height)
        }
    }

    // Map touch point in view-local UI points to the 1024×768 logical
    // surface DXMT swapchains use, then post to winios.drv. Coordinates
    // are relative to the aspect-fit gameRect (letterbox borders clamp).
    private func mapTouch(_ touch: UITouch) -> (Int32, Int32) {
        let p = touch.location(in: self)
        let r = gameRect()
        let x = Int32(min(max((p.x - r.minX) * 1024 / r.width, 0), 1023))
        let y = Int32(min(max((p.y - r.minY) * 768 / r.height, 0), 767))
        return (x, y)
    }

    // ==================================================================
    // S2 desktop mode: trackpad-style pointer.
    //   one finger move       — cursor moves relative (like a laptop pad)
    //   single tap            — left click
    //   double tap            — double click (two rapid clicks)
    //   double tap + hold     — drag (button held while moving), lift = drop
    //   two-finger drag       — scroll wheel
    //   two-finger tap        — right click
    // Cursor position lives here (desktop px); wine + the rendered arrow
    // follow via winios_pointer / winios_cursor_move.
    // ==================================================================
    private static var cursor = CGPoint(x: 480, y: 270)
    private var lastPanPoint = CGPoint.zero
    private var touchStartPoint = CGPoint.zero
    private var touchStartTime: TimeInterval = 0
    private var movedBeyondSlop = false
    private var dragActive = false
    private var dragTouch: UITouch?          // the finger that owns the drag
    private var touchGeneration = 0          // invalidates pending long-press timers
    private var twoFingerActive = false
    private var twoFingerMoved = false
    private var twoFingerStartTime: TimeInterval = 0
    private var lastTwoFingerY: CGFloat = 0
    private var scrollAccum: CGFloat = 0

    private let F_MOVE: UInt32 = 0x1, F_LDOWN: UInt32 = 0x2, F_LUP: UInt32 = 0x4
    private let F_RDOWN: UInt32 = 0x8, F_RUP: UInt32 = 0x10
    private let F_WHEEL: UInt32 = 0x800, F_ABS: UInt32 = 0x8000

    private var desktopMode: Bool {
        guard let v = getenv("MYTHIC_DESKTOP") else { return false }
        return v.pointee == 49  // '1'
    }
    private func envInt(_ name: String, _ def: Int) -> Int {
        guard let v = getenv(name), let i = Int(String(cString: v)) else { return def }
        return i
    }
    private func postPointer(_ flags: UInt32, data: Int32 = 0) {
        winios_pointer(Int32(Self.cursor.x), Int32(Self.cursor.y), flags, UInt32(bitPattern: data))
    }
    private func avgPoint(_ touches: [UITouch]) -> CGPoint {
        var x: CGFloat = 0, y: CGFloat = 0
        for t in touches { let p = t.location(in: self); x += p.x; y += p.y }
        let n = CGFloat(max(touches.count, 1))
        return CGPoint(x: x / n, y: y / n)
    }
    private func activeTouches(_ event: UIEvent?) -> [UITouch] {
        (event?.allTouches ?? []).filter { $0.phase != .ended && $0.phase != .cancelled }
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard desktopMode else {
            guard let t = touches.first else { return }
            let (x, y) = mapTouch(t)
            winios_post_touch_down(x, y)
            return
        }
        let now = Date().timeIntervalSinceReferenceDate
        let active = activeTouches(event)
        touchGeneration += 1
        if active.count >= 2 {
            twoFingerActive = true
            twoFingerMoved = false
            twoFingerStartTime = now
            lastTwoFingerY = avgPoint(active).y
            scrollAccum = 0
            // a drag started by the first finger stays active; harmless
            return
        }
        guard let t = touches.first else { return }
        let p = t.location(in: self)
        touchStartPoint = p
        lastPanPoint = p
        touchStartTime = now
        movedBeyondSlop = false
        // long-press → drag: hold still for 0.5s, haptic confirms, then move
        // the window; release drops. (Replaced double-tap-hold — it raced
        // Windows' double-click detection: wine saw WM_LBUTTONDBLCLK.)
        let gen = touchGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self, self.touchGeneration == gen, !self.dragActive,
                  !self.movedBeyondSlop, !self.twoFingerActive else { return }
            self.dragActive = true
            self.dragTouch = t
            self.postPointer(self.F_LDOWN)
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            fputs("[trackpad] long-press drag armed\n", stderr)
        }
    }

    override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard desktopMode else {
            guard let t = touches.first else { return }
            let (x, y) = mapTouch(t)
            winios_post_touch_move(x, y)
            return
        }
        let active = activeTouches(event)
        if twoFingerActive {
            guard active.count >= 2 else { return }
            let avg = avgPoint(active)
            let dy = avg.y - lastTwoFingerY
            lastTwoFingerY = avg.y
            if abs(dy) > 2 { twoFingerMoved = true }
            scrollAccum += dy
            // 14pt of finger travel = one wheel notch; fingers up = wheel up
            while scrollAccum <= -14 { scrollAccum += 14; postPointer(F_WHEEL, data: 120) }
            while scrollAccum >= 14 { scrollAccum -= 14; postPointer(F_WHEEL, data: -120) }
            return
        }
        let t: UITouch
        if dragActive, let d = dragTouch {
            guard touches.contains(d) else { return }  // only the old tap finger moved
            t = d
        } else {
            guard let f = touches.first else { return }
            t = f
        }
        let p = t.location(in: self)
        let dx = p.x - lastPanPoint.x, dy = p.y - lastPanPoint.y
        lastPanPoint = p
        if hypot(p.x - touchStartPoint.x, p.y - touchStartPoint.y) > 10 { movedBeyondSlop = true }
        let sens: CGFloat = 2.0   // desktop px per view pt
        let maxX = CGFloat(envInt("MYTHIC_SCREEN_W", 1024) - 1)
        let maxY = CGFloat(envInt("MYTHIC_SCREEN_H", 768) - 1)
        Self.cursor.x = min(max(Self.cursor.x + dx * sens, 0), maxX)
        Self.cursor.y = min(max(Self.cursor.y + dy * sens, 0), maxY)
        postPointer(F_MOVE | F_ABS)
    }

    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard desktopMode else {
            guard let t = touches.first else { return }
            let (x, y) = mapTouch(t)
            winios_post_touch_up(x, y)
            return
        }
        let now = Date().timeIntervalSinceReferenceDate
        if twoFingerActive {
            if activeTouches(event).isEmpty {
                if !twoFingerMoved && now - twoFingerStartTime < 0.40 {
                    postPointer(F_RDOWN)
                    postPointer(F_RUP)
                }
                twoFingerActive = false
            }
            return
        }
        touchGeneration += 1   // cancel any pending long-press
        if dragActive {
            if let d = dragTouch, !touches.contains(d) {
                fputs("[trackpad] ended: non-drag finger up (drag continues)\n", stderr)
                return
            }
            fputs("[trackpad] ended: drag drop\n", stderr)
            postPointer(F_LUP)
            dragActive = false
            dragTouch = nil
            return
        }
        // stationary release before the 0.5s drag threshold = click
        if !movedBeyondSlop && now - touchStartTime < 0.5 {
            fputs("[trackpad] ended: click\n", stderr)
            postPointer(F_LDOWN)
            postPointer(F_LUP)
        }
    }

    override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard desktopMode else {
            guard let t = touches.first else { return }
            let (x, y) = mapTouch(t)
            winios_post_touch_up(x, y)
            return
        }
        fputs("[trackpad] CANCELLED (dragActive=\(dragActive))\n", stderr)
        touchGeneration += 1
        if dragActive { postPointer(F_LUP); dragActive = false }
        dragTouch = nil
        twoFingerActive = false
    }
}

/// Arrow-key button with press/hold/release semantics. DragGesture with
/// zero minimum distance fires onChanged at touch-down (key down once)
/// and onEnded at lift (key up) — unlike Button, which only taps.
struct HoldKeyView: View {
    let label: String
    let vk: Int32
    var big = false   // landscape D-pad: thumb-sized
    @State private var isDown = false

    var body: some View {
        Text(label)
            .font(.system(size: big ? 22 : 14, weight: .semibold, design: .monospaced))
            .foregroundColor(.white)
            .frame(minWidth: big ? 56 : 34, minHeight: big ? 56 : 30)
            .background(Color.white.opacity(isDown ? 0.35 : 0.15))
            .cornerRadius(big ? 12 : 6)
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { _ in
                        if !isDown {
                            isDown = true
                            winios_post_key(vk, 1)
                        }
                    }
                    .onEnded { _ in
                        isDown = false
                        winios_post_key(vk, 0)
                    }
            )
    }
}

/// Shared state for the expanded thumbstick pad. The pad cannot be drawn by
/// SwiftUI in place: the game surface is a raw window-level UIView
/// (MetalHostView.shared) sitting ABOVE the entire SwiftUI hierarchy, so a
/// SwiftUI pad centred on the key row gets sliced off wherever it overlaps —
/// no zIndex can fix that, because zIndex only orders siblings *within*
/// SwiftUI. So the pad is hosted in the window too, added after (and thus
/// above) the Metal view, and driven from the SwiftUI button through this.
final class JoystickPadState: ObservableObject {
    static let shared = JoystickPadState()
    @Published var held = false
    @Published var dir: Int = -1
    @Published var center: CGPoint = .zero      // window coordinates
}

/// Window-level host for the pad. Transparent and non-interactive: the
/// SwiftUI button keeps the gesture, this only draws.
enum JoystickPadHost {
    /// Own UIWindow, one level above the app's. Being a sibling subview of
    /// MetalHostView is NOT enough: that view re-adds itself to the window on
    /// every didMoveToWindow (rotation, re-attach) and DXMT/CoreAnimation can
    /// reorder around it, so any subview ordering we impose is only true until
    /// the next layout. A higher windowLevel cannot be undone by anything
    /// inside the app window, so the pad is unconditionally on top.
    ///
    /// Deliberately NOT solved by changing the game surface: the CAMetalLayer
    /// is window-level precisely because SwiftUI hosting silently dropped
    /// presents on iOS 26/27 (see MetalHostView) — that is a rendering
    /// correctness fix and must not be traded away for z-ordering.
    private static var overlay: PassthroughWindow?

    static func attach(to scene: UIWindowScene) {
        if overlay == nil {
            let w = PassthroughWindow(windowScene: scene)
            w.windowLevel = .normal + 100
            w.backgroundColor = .clear
            w.isHidden = false                 // never becomes key: see PassthroughWindow
            let host = UIHostingController(rootView: JoystickPadOverlay())
            host.view.backgroundColor = .clear
            host.view.isUserInteractionEnabled = false
            w.rootViewController = host
            overlay = w
        }
        overlay?.frame = scene.coordinateSpace.bounds
    }
}

/// Transparent, fully click-through window: hitTest always returns nil, so
/// touches fall through to the app window underneath and the pad can never
/// steal input from the game surface or the SwiftUI controls.
final class PassthroughWindow: UIWindow {
    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? { nil }
}

/// The expanded pad, drawn in window space at the button's location.
struct JoystickPadOverlay: View {
    @ObservedObject private var s = JoystickPadState.shared

    var body: some View {
        GeometryReader { _ in
            // THE one and only joystick face — idle ring and expanded pad are
            // the same view, never two that swap. That identity is what makes
            // it seamless: the diameter and the knob offset are plain animated
            // properties, so releasing lets the knob spring back to centre and
            // keep wiggling after the ring has already shrunk. Two faces
            // cross-fading (one in the button, one here) cannot do that — the
            // wiggle dies with the copy that gets faded out.
            //
            // Fixed-size box at a CONSTANT offset. Deliberately not
            // .position() + .transition(.scale): .position expands the view to
            // fill the parent (so a .center anchor means mid-screen), and an
            // offset that changes in the same transaction as `held` gets
            // animated too — which is what made the pad fly in from the top.
            // Here the only animatable quantities belong to the face itself.
            JoystickFace(held: s.held, dir: s.dir)
                .frame(width: JoystickFace.padRadius * 2,
                       height: JoystickFace.padRadius * 2)
                .offset(x: s.center.x - JoystickFace.padRadius,
                        y: s.center.y - JoystickFace.padRadius)
                .opacity(s.center == .zero ? 0 : 1)
        }
        // MUST ignore the safe area. s.center comes from the button's .global
        // frame, which is measured from the WINDOW origin; without this the
        // overlay's hosting view is inset by the safe area, the offset above
        // is measured from below the status bar, and the pad lands ~59pt too
        // low — roughly one pad radius, which is exactly why it appeared to
        // sit under the game strip instead of centred on the button.
        .ignoresSafeArea()
        .allowsHitTesting(false)
        .animation(.spring(response: 0.32, dampingFraction: 0.62), value: s.held)
        .animation(.spring(response: 0.22, dampingFraction: 0.58), value: s.dir)
    }
}

/// The joystick face itself, shared by the in-row idle ring and the expanded
/// window-level pad so both look identical and animate the same way.
struct JoystickFace: View {
    var held: Bool
    var dir: Int

    static let idleDiameter: CGFloat = 22
    static let padRadius: CGFloat = 58
    private var idleDiameter: CGFloat { Self.idleDiameter }
    private var padRadius: CGFloat { Self.padRadius }
    private let knobTravelRatio: CGFloat = 0.30

    @ViewBuilder private var interior: some View {
        if #available(iOS 26.0, *) {
            Circle().fill(.clear).glassEffect(.regular, in: Circle())
        } else {
            Circle().fill(.ultraThinMaterial)
        }
    }

    private func knobOffset(_ d: CGFloat) -> CGSize {
        guard dir >= 0, held else { return .zero }
        let travel = d * knobTravelRatio
        let a = Double(dir) * 45.0 * .pi / 180.0
        return CGSize(width: travel * CGFloat(sin(a)), height: -travel * CGFloat(cos(a)))
    }

    var body: some View {
        let d = held ? padRadius * 2 : idleDiameter
        return ZStack {
            interior
            Circle().strokeBorder(Color.white.opacity(0.55), lineWidth: held ? 2 : 1.5)
            Circle()
                .fill(Color.white)
                .frame(width: d * 0.42, height: d * 0.42)
                .overlay(
                    // Roundness cue. It reads at key size but turns into a
                    // smudge on the big pad, so it fades out as the ring
                    // springs open rather than scaling up with it.
                    Circle()
                        .trim(from: 0.55, to: 0.70)
                        .stroke(Color.black.opacity(0.38),
                                style: StrokeStyle(lineWidth: 1.4, lineCap: .round))
                        .padding(d * 0.075)
                        .opacity(held ? 0 : 1)
                )
                .offset(knobOffset(d))
        }
        .frame(width: d, height: d)
    }
}

/// On-screen thumbstick. Idle it is a key-sized ring with a white knob;
/// press and hold and it expands into a pad you can steer. Travel snaps to
/// eight d-pad directions, each mapped to the arrow keys Windows games
/// already understand — diagonals simply hold two keys at once — so this
/// needs no new input path: it posts through the same winios_post_key queue
/// as the key buttons, and key state is edge-triggered (only the keys that
/// actually changed are sent on each snap).
///
/// The pad expands DOWNWARD. It must never grow up into the game strip:
/// that surface is a raw window-level UIView (MetalHostView.shared) drawn
/// over SwiftUI, so anything overlapping it is simply covered.
struct JoystickKeyView: View {
    @State private var held = false
    @State private var dir: Int = -1        // -1 = centred, else 0=up then clockwise
    @State private var center: CGPoint = .zero
    @State private var hosted = false       // overlay window up: it draws the face

    private let deadzone: CGFloat = 14      // pt of travel before a direction registers

    private let vkUp: Int32 = 0x26, vkRight: Int32 = 0x27
    private let vkDown: Int32 = 0x28, vkLeft: Int32 = 0x25

    private func keys(for d: Int) -> [Int32] {
        switch d {
        case 0: return [vkUp]
        case 1: return [vkUp, vkRight]
        case 2: return [vkRight]
        case 3: return [vkDown, vkRight]
        case 4: return [vkDown]
        case 5: return [vkDown, vkLeft]
        case 6: return [vkLeft]
        case 7: return [vkUp, vkLeft]
        default: return []
        }
    }

    /// Release what is no longer held, press what newly is — never a blanket
    /// release/re-press, which would make a held direction stutter as the
    /// thumb wanders inside one sector.
    private func apply(_ next: Int) {
        guard next != dir else { return }
        let old = Set(keys(for: dir)), new = Set(keys(for: next))
        for vk in old.subtracting(new) { winios_post_key(vk, 0) }
        for vk in new.subtracting(old) { winios_post_key(vk, 1) }
        dir = next
        JoystickPadState.shared.dir = next
    }

    private func snap(_ t: CGSize) -> Int {
        let d = (t.width * t.width + t.height * t.height).squareRoot()
        if d < deadzone { return -1 }
        // Screen y grows downward; measure clockwise from "up".
        var a = atan2(t.width, -t.height) * 180 / .pi
        if a < 0 { a += 360 }
        return Int((a + 22.5) / 45.0) % 8
    }

    var body: some View {
        // The idle ring lives in the row (inset inside the 34x30 button so it
        // has breathing room). The EXPANDED pad is drawn by the window-level
        // host at this same centre — see JoystickPadState — so it springs out
        // of the button in place and is never clipped by the game surface.
        Color.clear
            .frame(width: 34, height: 30)
            .background(Color.white.opacity(held ? 0.30 : 0.15))
            .cornerRadius(6)
            .overlay { if !hosted { JoystickFace(held: false, dir: -1) } }
            .background(
                GeometryReader { geo in
                    Color.clear.onAppear {
                        center = CGPoint(x: geo.frame(in: .global).midX,
                                         y: geo.frame(in: .global).midY)
                        JoystickPadState.shared.center = center
                        if let scene = UIApplication.shared.connectedScenes
                            .compactMap({ $0 as? UIWindowScene }).first {
                            JoystickPadHost.attach(to: scene)
                            hosted = true
                        }
                    }
                    .onChange(of: geo.frame(in: .global)) { _, f in
                        center = CGPoint(x: f.midX, y: f.midY)
                        JoystickPadState.shared.center = center
                    }
                }
            )
            .animation(.spring(response: 0.32, dampingFraction: 0.62), value: held)
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { g in
                        if !held {
                            held = true
                            if let scene = UIApplication.shared.connectedScenes
                                .compactMap({ $0 as? UIWindowScene }).first {
                                JoystickPadHost.attach(to: scene)
                            }
                            JoystickPadState.shared.center = center
                            withAnimation(.spring(response: 0.32, dampingFraction: 0.62)) {
                                JoystickPadState.shared.held = true
                            }
                        }
                        apply(snap(g.translation))
                    }
                    .onEnded { _ in
                        apply(-1)                        // releases every held arrow
                        held = false
                        withAnimation(.spring(response: 0.32, dampingFraction: 0.62)) {
                            JoystickPadState.shared.held = false
                        }
                    }
            )
    }
}

// SwiftUI wrapper around the placeholder view.
// iOS software-keyboard → Wine key events. Each character is mapped to a
// US-layout virtual-key (+ shift where needed) and posted as a down/up pair;
// the message queue's ToUnicode then produces the right WM_CHAR. Paths need
// the full symbol set (":" "\" "-" "." "_"), so the table is comprehensive.
extension MetalBackedView: UIKeyInput {
    var hasText: Bool { false }

    // US-keyboard VK + shift for a character. Returns nil for chars we can't map.
    private static func vkForChar(_ ch: Character) -> (Int32, Bool)? {
        if ch == "\n" || ch == "\r" { return (0x0D, false) }   // VK_RETURN
        if ch == "\t" { return (0x09, false) }                 // VK_TAB
        if ch == " " { return (0x20, false) }                  // VK_SPACE
        if ch.isLetter, let up = ch.uppercased().first?.asciiValue, up >= 0x41, up <= 0x5A {
            return (Int32(up), ch.isUppercase)                 // VK_A..VK_Z
        }
        if let a = ch.asciiValue, a >= 0x30, a <= 0x39 {
            return (Int32(a), false)                           // VK_0..VK_9 (unshifted)
        }
        let table: [Character: (Int32, Bool)] = [
            "!": (0x31, true), "@": (0x32, true), "#": (0x33, true), "$": (0x34, true),
            "%": (0x35, true), "^": (0x36, true), "&": (0x37, true), "*": (0x38, true),
            "(": (0x39, true), ")": (0x30, true),
            "-": (0xBD, false), "_": (0xBD, true),
            "=": (0xBB, false), "+": (0xBB, true),
            "[": (0xDB, false), "{": (0xDB, true),
            "]": (0xDD, false), "}": (0xDD, true),
            "\\": (0xDC, false), "|": (0xDC, true),
            ";": (0xBA, false), ":": (0xBA, true),
            "'": (0xDE, false), "\"": (0xDE, true),
            ",": (0xBC, false), "<": (0xBC, true),
            ".": (0xBE, false), ">": (0xBE, true),
            "/": (0xBF, false), "?": (0xBF, true),
            "`": (0xC0, false), "~": (0xC0, true),
        ]
        return table[ch]
    }

    func insertText(_ text: String) {
        for ch in text {
            guard let (vk, shift) = MetalBackedView.vkForChar(ch) else { continue }
            if shift { winios_post_key(0x10, 1) }   // VK_SHIFT down
            winios_post_key(vk, 1)
            winios_post_key(vk, 0)
            if shift { winios_post_key(0x10, 0) }    // VK_SHIFT up
        }
    }

    func deleteBackward() {
        winios_post_key(0x08, 1)   // VK_BACK down
        winios_post_key(0x08, 0)
    }

    // Traits: keep iOS from rewriting path characters.
    var keyboardType: UIKeyboardType { get { .asciiCapable } set {} }
    var autocorrectionType: UITextAutocorrectionType { get { .no } set {} }
    var autocapitalizationType: UITextAutocapitalizationType { get { .none } set {} }
    var smartQuotesType: UITextSmartQuotesType { get { .no } set {} }
    var smartDashesType: UITextSmartDashesType { get { .no } set {} }
    var spellCheckingType: UITextSpellCheckingType { get { .no } set {} }
}

struct MythicMetalView: UIViewRepresentable {
    func makeUIView(context: Context) -> MetalBackedView {
        return MetalBackedView(frame: CGRect(x: 0, y: 0, width: 800, height: 600))
    }
    func updateUIView(_ uiView: MetalBackedView, context: Context) {}
}

struct ContentView: View {
    @StateObject private var logStore = LogStore.shared
    @State private var jitStatus: JITStatus = .unknown
    @State private var entitlements: EntitlementStatus?
    @State private var showSetupGuide = false
    @State private var debuggerAttached = isDebuggerAttached()
    /// .compact = iPhone landscape: game surface expands, arrow keys appear.
    @Environment(\.verticalSizeClass) private var vSizeClass

    enum JITStatus {
        case unknown
        case testing
        case available
        case mappingOnly
        case unavailable
    }

    var body: some View {
        NavigationView {
            Group {
                if vSizeClass == .compact {
                    landscapeBody
                } else {
                    portraitBody
                }
            }
            // Rotation destroys/recreates the UIViewRepresentable across
            // this if/else (two SwiftUI identities) — HARMLESS since
            // 2026-07-05: MetalHostView is a process-lifetime singleton;
            // a fresh placeholder only re-parents the same CAMetalLayer.
            .navigationTitle("Mythic")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarHidden(vSizeClass == .compact)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showSetupGuide = true }) {
                        Image(systemName: "questionmark.circle")
                    }
                }
            }
            .sheet(isPresented: $showSetupGuide) {
                SetupGuideView()
            }
            .onAppear {
                jit_install_trap_handler()
                entitlements = EntitlementStatus.check()
                logEntitlementStatus()
            }
        }
    }

    /// Portrait: classic tooling layout — header, badges, 240pt game strip,
    /// key row, action buttons, log console.
    private var portraitBody: some View {
        VStack(spacing: 0) {
            statusHeader
            // Readouts sit ABOVE the game strip, closest to the surface they
            // describe: entitlement indicators, then the present/FPS readout,
            // then the surface itself. (Only the KEY row stays below — it is
            // input, not instrumentation.)
            //
            // NOTE: the surface is a raw window-level view positioned over the
            // placeholder (MetalHostView.shared), so SwiftUI content laid "on
            // top" of the strip is covered — these rows must be siblings above
            // it, never overlays on it.
            if let ents = entitlements {
                entitlementBadges(ents)
            }
            HStack(spacing: 6) {
                FPSOverlay()
                Spacer()
            }
            .padding(.horizontal, 8)
            .padding(.bottom, 4)
            MythicMetalView()
                .frame(height: 240)
                .background(Color.black)
            HStack(spacing: 6) {
                keyButton("⏎", vk: 0x0D)   // VK_RETURN
                keyButton("␣", vk: 0x20)   // VK_SPACE
                keyButton("Esc", vk: 0x1B) // VK_ESCAPE
                Button { MetalBackedView.toggleKeyboard() } label: {
                    Text("⌨").font(.system(size: 20))
                        .frame(minWidth: 40, minHeight: 32)
                        .background(Color.secondary.opacity(0.25))
                        .cornerRadius(6)
                }
                JoystickKeyView()
                Spacer()
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            // The expanded pad overflows this row; without a raised zIndex the
            // later VStack siblings (action buttons, log) would draw over it.
            .zIndex(10)
            Divider()
            actionButtons
            Divider()
            logConsole
        }
    }

    /// Landscape: game mode. Full-height 4:3 surface centered (aspect-fit
    /// happens in MetalBackedView); ALL controls live in the pillarbox
    /// bars left/right of the game — the window-level surface would cover
    /// anything drawn over the game area itself. No header/log/nav chrome.
    private var landscapeBody: some View {
        GeometryReader { geo in
            let gameW = min(geo.size.width, geo.size.height * 4.0 / 3.0)
            let barW = max((geo.size.width - gameW) / 2.0, 44)
            ZStack {
                Color.black
                MythicMetalView()
                HStack(spacing: 0) {
                    // Left bar: D-pad (hold semantics — Thumper's turns
                    // are held keys).
                    VStack(spacing: 12) {
                        Spacer()
                        holdKeyButton("▲", vk: 0x26, big: true)
                        HStack(spacing: 16) {
                            holdKeyButton("◀", vk: 0x25, big: true)
                            holdKeyButton("▶", vk: 0x27, big: true)
                        }
                        holdKeyButton("▼", vk: 0x28, big: true)
                        Spacer()
                    }
                    .frame(width: barW)
                    Spacer(minLength: 0)
                    // Right bar: FPS readout (compact) + menu keys.
                    VStack(spacing: 12) {
                        FPSOverlay(compact: true)
                        Spacer()
                        keyButton("⏎", vk: 0x0D)
                        keyButton("␣", vk: 0x20)
                        keyButton("Esc", vk: 0x1B)
                        Spacer()
                    }
                    .frame(width: barW)
                }
            }
        }
        .ignoresSafeArea()
        .background(Color.black)
    }

    private var statusHeader: some View {
        HStack {
            // The "JIT Status" row only ever read "Not tested" — this probe was
            // never wired to the live state, and the real JIT indicator sits
            // directly below it. Removed rather than left lying (a status line
            // that cannot change is worse than none). statusColor/statusText
            // are kept: enableJITViaStikDebug() and the JIT self-tests still
            // drive jitStatus, so re-adding a row is a one-liner if wanted.
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Text("Device")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(deviceInfo)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
    }

    /// Hold-to-press key: VK down on touch, VK up on release — for keys
    /// games treat as held (arrows). Same winios queue as keyButton.
    private func holdKeyButton(_ label: String, vk: Int32, big: Bool = false) -> some View {
        HoldKeyView(label: label, vk: vk, big: big)
    }

    /// Small on-screen key: posts VK down, then up 60ms later, through the
    /// winios input queue (same path as touch→mouse).
    private func keyButton(_ label: String, vk: Int32) -> some View {
        Button(action: {
            winios_post_key(vk, 1)
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.06) {
                winios_post_key(vk, 0)
            }
        }) {
            Text(label)
                .font(.system(size: 14, weight: .semibold, design: .monospaced))
                .foregroundColor(.white)
                .frame(minWidth: 34, minHeight: 30)
                .background(Color.white.opacity(0.15))
                .cornerRadius(6)
        }
    }

    private func entitlementBadges(_ ents: EntitlementStatus) -> some View {
        HStack(spacing: 8) {
            // Live debugger/JIT state, not the (macOS-only, never granted on
            // iOS) allow-jit entitlement the old badge checked.
            entitlementBadge("JIT", granted: debuggerAttached)
            entitlementBadge("Memory+", granted: ents.increasedMemory)
            entitlementBadge("64-bit VA", granted: ents.extendedVA)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.bottom, 8)
        .onReceive(Timer.publish(every: 2, on: .main, in: .common).autoconnect()) { _ in
            debuggerAttached = isDebuggerAttached()
        }
    }

    private func entitlementBadge(_ label: String, granted: Bool) -> some View {
        HStack(spacing: 4) {
            Image(systemName: granted ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundColor(granted ? .green : .orange)
                .font(.caption2)
            Text(label)
                .font(.caption2)
                .foregroundColor(granted ? .primary : .secondary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(granted ? Color.green.opacity(0.1) : Color.orange.opacity(0.1))
        )
    }

    private func logEntitlementStatus() {
        guard let ents = entitlements else { return }
        logStore.log("Checking entitlements...")
        logStore.log("  allow-jit: \(ents.jitAllowed)", level: ents.jitAllowed ? .success : .error)
        logStore.log("  increased-memory-limit: \(ents.increasedMemory)", level: ents.increasedMemory ? .success : .debug)
        logStore.log("  extended-virtual-addressing: \(ents.extendedVA)", level: ents.extendedVA ? .success : .debug)
        if !ents.extendedVA {
            logStore.log("  Tip: Use GetMoreRam to inject extended-virtual-addressing", level: .info)
        }
    }

    private var actionButtons: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                Button("Enable JIT") {
                    enableJITViaStikDebug()
                }
                .buttonStyle(.borderedProminent)

                Button("🎮 Run Steam (S3 smoke test)") {
                    // Steam S3 first boot: virtual desktop (Steam needs a
                    // window manager) + services.exe (SCM → rpcss for Steam's
                    // COM, the chain proven in the rpcss milestone) + steam.exe
                    // itself, all launched by C:\steam-launch.bat (pushed to
                    // the prefix). Batch avoids quote-escaping hell; combase's
                    // 5s OpenSCManager retry covers the services-vs-steam race.
                    // Steam install = CrossOver copy at C:\Program Files (x86)\
                    // Steam (all boot binaries verified x86-64; steamwebhelper
                    // /libcef = 209MB → watch pool: first webhelper may fit,
                    // multiples need .text sharing). Flags: -no-cef-sandbox
                    // (sandbox can't work in Wine), -cef-disable-gpu (software
                    // render), -console (Steam's own log → our stderr). Steam
                    // WILL try to self-update through our GnuTLS stack — that
                    // attempt is itself an informative S0 re-test.
                    let deskW = 1024, deskH = 768
                    setenv("MYTHIC_EXE", "explorer.exe", 1)
                    setenv("MYTHIC_ARGS",
                           "/desktop=shell,\(deskW)x\(deskH) cmd /c C:\\steam-launch.bat", 1)
                    setenv("MYTHIC_DESKTOP", "1", 1)
                    setenv("MYTHIC_SCREEN_W", String(deskW), 1)
                    setenv("MYTHIC_SCREEN_H", String(deskH), 1)
                    // ml371: surfdump ground truth — the "frozen desktop"
                    // question (fresh pixels never presented vs nothing
                    // painting upstream) is undecidable from the log alone
                    // because the [winios] present line caps at 12.
                    setenv("MYTHIC_DUMP_SURFACES", "1", 1)
                    // ml493: bursts of N CONSECUTIVE frames per window. The
                    // login window's black regions change every frame, which
                    // the 2s-throttled first/latest dump can never show —
                    // adjacent frames are the only way to measure what moves.
                    setenv("MYTHIC_SURF_SEQ", "10", 1)
                    // ml515: SRCWATCH RE-ENABLED, now hooked in the MACH
                    // exception handler (where guest faults are actually
                    // delivered) instead of segv_handler. It consumes its own
                    // faults BEFORE every other classification and marks them
                    // handled via the canonical thread_set_state path, so a
                    // protection fault can no longer reach the guest as an AV.
                    // ml514 hooked the wrong path: 0 faults, black window 2/2.
                    setenv("MYTHIC_SRCWATCH", "1", 1)
                    // ml514 note (kept for the record): The ml514 watch
                    // armed correctly (76 pages protected) but logged ZERO
                    // faults and produced an all-black window on two runs: the
                    // hook went in the BSD segv_handler, while guest faults in
                    // this port are handled IN-MACH by the exception server, so
                    // the protection fault was delivered to the guest as an AV
                    // and killed Chromium's paint. A probe must never break the
                    // path it measures. To revive it, hook the Mach exception
                    // server (where ios_emulate_unaligned_guest_access already
                    // runs), not segv_handler, and re-enable this env var.
                    // ml502 sentinel: DELIBERATELY NOT ENABLED. It stamps
                    // magenta into currently-black pixels, and on windows
                    // Chromium does not fully rewrite it SURVIVES and reaches
                    // the screen (console 0x200bc hit untouched=177891 in one
                    // round). It answered its question in ml503/ml504 —
                    // untouched=0 on the login window proved Chromium writes
                    // every pixel — so it must not ship enabled. Re-enable
                    // with MYTHIC_SURF_SENTINEL=1 if the question returns.
                    runWineFullSequence()
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)

                Button("Run Desktop + services (R2v2)") {
                    // S3-pre R2v2: raw rpcss.exe CANNOT run standalone —
                    // its wmain unconditionally StartServiceCtrlDispatcherW's
                    // (rpcss_main.c:282), which RPCs back to the SCM; without
                    // services.exe it raised + wedged in
                    // service_run_main_thread, and explorer's
                    // CoRegisterClassObject wedged behind it (seq-3680 run).
                    // Proper bootstrap: explorer's cmdline child = services.exe
                    // (SCM host, windows-subsystem = no console). It creates
                    // \pipe\svcctl early, runs auto-start services (MountMgr/
                    // Eventlog/NDIS/nsiproxy/PlugPlay — winedevice/plugplay
                    // are bundled; failures tolerated), and combase's
                    // start_rpcss then demand-starts RpcSs through the SCM
                    // with a 30s start-pending wait → rpcss runs as services'
                    // child (3-deep tree, proven depth) with a proper
                    // dispatcher connection → epmapper up → real COM.
                    // Known risk: if shellwindows_init beats services.exe's
                    // RPC_Init, OpenSCManager fails → watch whether that
                    // fails fast or hits the RaiseException→CS wedge again.
                    let deskW = 960, deskH = 540
                    setenv("MYTHIC_EXE", "explorer.exe", 1)
                    setenv("MYTHIC_ARGS",
                           "/desktop=shell,\(deskW)x\(deskH) C:\\windows\\system32\\services.exe", 1)
                    setenv("MYTHIC_DESKTOP", "1", 1)
                    setenv("MYTHIC_SCREEN_W", String(deskW), 1)
                    setenv("MYTHIC_SCREEN_H", String(deskH), 1)
                    runWineFullSequence()
                }
                .buttonStyle(.borderedProminent)
                .tint(.mint)

                Button("Run Thumper (D3D11 / win10)") {
                    // Game lives at Documents/wine/drive_c/Program Files/Thumper/
                    // (push via scripts/deploy-thumper.sh during development;
                    // bundled as resource for distribution later).
                    setenv("MYTHIC_EXE",
                           "C:\\Program Files\\Thumper\\THUMPER_win10.exe", 1)
                    unsetenv("MYTHIC_ARGS")
                    unsetenv("MYTHIC_DESKTOP")
                    runWineFullSequence()
                }
                .buttonStyle(.borderedProminent)
                .tint(.pink)

                Button("Run x64 cube (FEX/ARM64EC + DXMT)") {
                    setenv("MYTHIC_EXE", "cube-x64.exe", 1)
                    unsetenv("MYTHIC_ARGS")
                    runWineFullSequence()
                }
                .buttonStyle(.borderedProminent)
                .tint(.purple)

                Button("Run D3D11 Triangle") {
                    runTriangleTest()
                }
                .buttonStyle(.borderedProminent)
                .tint(.blue)

                Button("Clear Log") {
                    logStore.clear()
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
            .padding()
        }
    }

    private func runTriangleTest() {
        logStore.log("D3D11 triangle test: full sequence", level: .info)
        // Reuse the existing full Wine sequence but target triangle.exe.
        // WineProcessBridge has the program baked in for now — to flip it
        // requires a signature change. For this iteration we rely on the
        // build's WineProcessBridge.m pointing at triangle.exe.
        runWineFullSequence()
    }

    private var logConsole: some View {
        let entries = logStore.entries.sorted(by: { $0.lastTimestamp > $1.lastTimestamp })
        return List(entries) { entry in
            HStack(alignment: .top, spacing: 8) {
                // Timestamp of LAST occurrence
                Text(timeString(entry.lastTimestamp))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.secondary)
                    .frame(width: 64, alignment: .leading)
                // Level chip
                Text(entry.level.rawValue)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(colorForLevel(entry.level))
                    .frame(width: 28, alignment: .leading)
                // Last raw message (the most recent line that matched this signature)
                Text(entry.lastRaw)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.primary)
                    .lineLimit(2)
                // Count badge (only if count > 1)
                if entry.count > 1 {
                    Text("×\(entry.count)")
                        .font(.system(.caption2, design: .monospaced).weight(.semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.2))
                        .cornerRadius(4)
                        .foregroundColor(.secondary)
                }
            }
            .listRowInsets(EdgeInsets(top: 2, leading: 8, bottom: 2, trailing: 8))
        }
        .listStyle(.plain)
    }

    private func timeString(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: date)
    }

    private var statusColor: Color {
        switch jitStatus {
        case .unknown: return .gray
        case .testing: return .yellow
        case .available: return .green
        case .mappingOnly: return .orange
        case .unavailable: return .red
        }
    }

    private var statusText: String {
        switch jitStatus {
        case .unknown: return "Not tested"
        case .testing: return "Testing..."
        case .available: return "Available"
        case .mappingOnly: return "Needs debugger"
        case .unavailable: return "Unavailable"
        }
    }

    private var deviceInfo: String {
        var sysinfo = utsname()
        uname(&sysinfo)
        let machine = withUnsafePointer(to: &sysinfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        return machine
    }

    private func colorForLevel(_ level: LogStore.LogEntry.Level) -> Color {
        switch level {
        case .info: return .blue
        case .success: return .green
        case .error: return .red
        case .debug: return .gray
        }
    }

    private func runJITTest() {
        jitStatus = .testing
        logStore.log("Starting JIT test...")

        DispatchQueue.global(qos: .userInitiated).async {
            let result = jit_test_execute()

            DispatchQueue.main.async {
                switch result {
                case 42:
                    jitStatus = .available
                    logStore.log("JIT is fully functional!", level: .success)
                case -2:
                    jitStatus = .unavailable
                    logStore.log("CS_DEBUGGED not set. Use StikDebug to enable JIT for this app.", level: .error)
                    DispatchQueue.global(qos: .userInitiated).async {
                        let mappingOk = jit_test_mapping()
                        DispatchQueue.main.async {
                            if mappingOk {
                                jitStatus = .mappingOnly
                                logStore.log("Dual mapping works. Enable JIT via StikDebug to unlock execution.", level: .success)
                            }
                        }
                    }
                case -3:
                    jitStatus = .unavailable
                    logStore.log("Fault loop detected — try 'Test JIT (Alt)' for debugger-allocated memory", level: .error)
                default:
                    jitStatus = .unavailable
                    logStore.log("JIT test failed with result: \(result)", level: .error)
                }
            }
        }
    }

    private func runJITTestStrategy2() {
        jitStatus = .testing
        logStore.log("Starting JIT test (Strategy 2: debugger-allocated RX)...")

        DispatchQueue.global(qos: .userInitiated).async {
            let result = jit_test_execute_strategy2()

            DispatchQueue.main.async {
                switch result {
                case 42:
                    jitStatus = .available
                    logStore.log("JIT is fully functional (strategy 2)!", level: .success)
                case -2:
                    jitStatus = .unavailable
                    logStore.log("CS_DEBUGGED not set. Use StikDebug to enable JIT.", level: .error)
                case -3:
                    jitStatus = .unavailable
                    logStore.log("Fault loop — debugger-allocated pages also rejected", level: .error)
                default:
                    jitStatus = .unavailable
                    logStore.log("Strategy 2 failed with result: \(result)", level: .error)
                }
            }
        }
    }

    private func runFEXTest() {
        logStore.log("Starting FEX-Emu integration test...")
        jitStatus = .testing

        // Set up FEX log callback
        fex_set_log_callback { msg in
            if let msg = msg {
                let str = String(cString: msg)
                DispatchQueue.main.async {
                    LogStore.shared.log(str, level: .debug)
                }
            }
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = fex_test_execute()

            DispatchQueue.main.async {
                switch result {
                case 42:
                    jitStatus = .available
                    logStore.log("FEX-Emu test PASSED: x86-64 code returned 42!", level: .success)
                case -1:
                    jitStatus = .unavailable
                    logStore.log("FEX-Emu test FAILED (init/setup error)", level: .error)
                default:
                    jitStatus = .unavailable
                    logStore.log("FEX-Emu test returned \(result)", level: .error)
                }
            }
        }
    }

    private func enableJITViaStikDebug() {
        jitStatus = .testing
        logStore.log("Requesting JIT via StikDebug URL scheme...")

        StikJITHelper.enableJIT { success in
            if success {
                jitStatus = .available
                logStore.log("JIT enabled! Debugger attached.", level: .success)
            } else {
                jitStatus = .unavailable
                logStore.log("Failed to enable JIT via StikDebug", level: .error)
            }
        }
    }

    /// Full sequence: allocate JIT pool, start wineserver, start Wine.
    /// Debugger stays attached during PE loading so mprotect_exec can use BRK
    /// to prepare code pages. Detach happens after Wine finishes + recovery.
    private func runWineFullSequence() {
        guard jit_check_debugged() else {
            logStore.log("JIT not enabled. Press 'Enable JIT' first.", level: .error)
            return
        }

        logStore.log("Running full Wine sequence...")

        // Start a main thread heartbeat to diagnose hang
        var heartbeatCount = 0
        let heartbeat = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            heartbeatCount += 1
            os_log("[HEARTBEAT] main thread alive #%d", heartbeatCount)
        }

        // Pause UI flushing — prevents ALL SwiftUI re-renders during Wine execution,
        // so zero main thread hang time accumulates while debugger is attached
        logStore.uiPaused = true

        // Suppress os_log from wineserver — hundreds of messages/sec cause os_log buffer
        // contention that blocks the main thread RunLoop, triggering iOS hang detection
        ws_log_quiet = 1

        DispatchQueue.global(qos: .userInitiated).async {
            // Step 1: Allocate JIT pool (BRK suspends entire process)
            // 128 MB was enough for cube but Thumper exhausts it (more PE
            // copies + larger FEX block cache). Desktop mode holds the
            // session's aarch64 image set AND every child's x64 set AND the
            // FEX code buffers in ONE pool: Thumper-under-desktop hit 199MB
            // of image copies alone (2026-07-06), leaving the FEX tail carve
            // colliding with the head. 384 MB fits both plus slack; the pool
            // is dual-map + NO_FOOTPRINT so unwritten pages cost nothing.
            //
            // 2026-07-10 (Steam S3): 384 MB is VIRTUAL-exhausted by Steam's
            // pseudo-process fan-out — steam.exe + services + rpcss + cmd +
            // conhost + steamerrorreporter64 each copy their whole DLL set
            // (owner-keyed, no .text sharing yet) → 138 image copies hit
            // ~365 MB and the crash reporter's ntdll can't fit → the load
            // fails and execution BUS-faults on the un-committed image. Since
            // the pool is jetsam-exempt + demand-committed (unwritten pages
            // cost nothing), raising the VIRTUAL cap is a cheap, safe unblock.
            // 640 MB clears the current fan-out with headroom to reach the
            // ole32 delay-load (FEX riprel probe) and beyond. The real fix for
            // the PHYSICAL duplication is .text sharing (deferred project).
            //
            // 2026-07-10 pm (task #34 / CEF): 896 MB — libcef.dll's 212MB
            // pool copy EXHAUSTED 640 (bump 412MB + no contiguous 212MB →
            // libcef load degraded → init CHECK). Pure-x64 skip-copy was
            // trialed and reverted (broke x18-trampoline layout, ml68);
            // until skip-copy or .text sharing lands, buy headroom. Virtual
            // is jetsam-exempt; the copy itself is ~212MB real RSS when
            // written.
            // 2026-08-01 (ml364): 1152 MB — ml363 died at MSM depth on pool
            // EXHAUSTION (bump 858MB, freelist 0, tail-reserve 64MB) when
            // Chrome's in-proc GPU thread requested a doubled 32MB EC code
            // buffer; the fallback landed non-executable in the guest band and
            // FEX scribbled through a garbage CodeBuffer. NOTE the jetsam
            // ledger note above is STALE: the pool was never exempt and
            // arrives FULLY DIRTY from StikDebug's TXM blessing writes, so
            // this +256MB costs +256MB of the 4096MB budget up front. The
            // ml362/ml363 footprint work (peak 3804→3190) is what pays for
            // it. The real fix for both sides is still .text sharing.
            // 2026-08-01 (ml367): back to 896 MB. ml364 needed 1152 because the
            // shipped PE DLLs carried DWARF debug sections (llvm-mingw links
            // -Wl,-debug:dwarf) and the pool copies the ENTIRE image, so 42% of
            // every copy was debug info with no runtime purpose. Stripping them
            // (llvm-strip --strip-debug over the bundle) drops projected peak
            // pool use 894 -> ~653 MB, so 896 restores the ml364-equivalent
            // headroom (~243 MB) while returning 256 MB of footprint — the pool
            // is dirty from birth, so its SIZE is what costs, not its usage.
            // KEEP ios_usable_va_floor PAIRED: 896MB -> 0x7038000000.
            // 2026-08-02 (ml421): 1024 MB. ml420 (post-#69-fix, deepest run yet:
            // cycle 41) refilled the stripped 896 pool anyway — head 768MB of
            // copies + 176MB tail of EC code buffers collided; the doubled 32MB
            // GPU-thread buffer was refused and the ml361/ml363 ClearCache
            // wild-write returned (now also honestly REFUSED unix-side,
            // rev=ml421). +128MB is the depth lever that fits under jetsam:
            // ml420 peaked 3837 phys; 3837+128=3965 < 4096. Tight — if jetsam
            // returns, the durable fix is .text sharing, not more pool.
            // 2026-08-02 (ml423): BACK to 896. Jetsam DID return — ml422 died a
            // silent EXC_RESOURCE kill at 2.5min (peak 3904, log stops mid-line),
            // exactly the predicted cost of the +128MB dirty-at-birth pool.
            // ml421's honest EC_CODE refusal makes pool exhaustion GRACEFUL now
            // (ctor halving, worst case one thread's 0xdead fault) while jetsam
            // kills the whole app — 896 + graceful degradation strictly beats
            // 1024 + jetsam roulette. Durable fix remains .text sharing.
            // KEEP ios_usable_va_floor PAIRED: 896MB -> 0x7038000000.
            // 2026-08-03 (ml458): STAY at 896 — growth is closed for good.
            // jetsam killed 1024 twice (ml422 peak 3904) and the no-footprint
            // exemption is unreachable: all four (entry-flags, owner) variants
            // return kr=4, and the plain ones expose why — the named entry
            // covers 16KB of the 896MB object, i.e. the kernel wants an entry
            // naming the WHOLE object, which we can never build over memory
            // whose object StikDebug created. Pool stays dirty-from-birth and
            // jetsam-counted, so SIZE is the cost and 896 is the ceiling.
            // ⛔ ml457 re-trialed pure-x64 skip-copy (already dead per ml68
            // above) and it failed again for a different reason: x64 guest
            // RIPs ARE pool-copy aliases, so the copy is the execution
            // substrate — steam.exe died in seconds. Do not try a third time.
            // The remaining levers are USE-side: the 276MB of duplicate copies
            // (.text sharing) and the 214MB tail of EC code buffers.
            let poolSizeMB = 896
            logStore.log("Allocating \(poolSizeMB)MB JIT pool (BRK will suspend process)...")
            let t0 = CFAbsoluteTimeGetCurrent()
            let pool = StikJITHelper.allocatePool(poolSize: poolSizeMB * 1024 * 1024)
            let elapsed = CFAbsoluteTimeGetCurrent() - t0
            logStore.log("BRK suspension lasted \(String(format: "%.2f", elapsed))s")

            if let pool = pool {
                logStore.log("JIT pool: RX=\(String(format: "%p", Int(bitPattern: pool.rx))), RW=\(String(format: "%p", Int(bitPattern: pool.rw))), size=\(pool.size / 1024 / 1024)MB", level: .success)
                setenv("WINE_IOS_JIT_RX", String(format: "%lx", Int(bitPattern: pool.rx)), 1)
                setenv("WINE_IOS_JIT_RW", String(format: "%lx", Int(bitPattern: pool.rw)), 1)
                setenv("WINE_IOS_JIT_SIZE", String(format: "%lx", pool.size), 1)
            } else {
                logStore.log("JIT pool allocation failed, continuing without it", level: .error)
            }

            // Step 2: Start wineserver
            self.startWineserver()

            // Step 3: Start Wine (debugger still attached for PE loading BRK calls)
            Thread.sleep(forTimeInterval: 2.0)
            self.startWineProcess()

            // Step 4: Wait for Wine to finish instead of fixed timer
            // Poll wine_process_is_running() — it clears when __wine_main returns
            // For real games this never returns (message loop runs forever), so
            // the cap is what matters. After detach, the dual-mapped JIT pool
            // keeps existing blocks executable; only NEW BRK-based compiles
            // fail.
            //
            // 2026-05-13 first-frame: Thumper splash renders at ~50s but JIT is
            // STILL compiling new FMOD blocks 3M log lines later — audio init
            // is huge (~14k unique RIPs in fmod64.dll alone). Bumped to 300s
            // to let FMOD finish init before debugger detach; otherwise main
            // game loop never engages because Present is gated on audio ready.
            logStore.log("Waiting for Wine to finish PE loading...")
            // 2026-07-03 early detach: attached-mode runs the whole guest
            // ~2x slower (measured 1.2s → 0.74s per present at detach) and
            // on iOS 27 presented frames only reliably reach glass after
            // detach. Post-detach is safe now: trap-mode JIT writes go via
            // the Mach emulator (no debugger), pool pages are pre-executable
            // (dual map), page0 runs once on the first thread, and a
            // post-detach compile was observed working (real_compiles
            // 7093→7094, no faults). So: detach once the game is actually
            // presenting (present #2 = first post-splash frame) plus a
            // settle window, instead of waiting out the full 1200s cap.
            let maxWait = 1200.0  // hard safety cap (unchanged)
            // 2026-07-03 second iteration: detach on present #1 (splash shown)
            // instead of #2. The 3-minute splash-hold is the game loading —
            // running it detached should roughly halve it. Riskier than #2
            // (thousands of load-time compiles + worker-thread spawns happen
            // post-detach) but all known dependencies are covered: trap-mode
            // writes, pre-executable pool, page0 once-guard.
            let settleAfterFirstPresent = 20.0
            var presentingSince: CFAbsoluteTime? = nil
            let pollStart = CFAbsoluteTimeGetCurrent()
            var lastHeartbeat = CFAbsoluteTimeGetCurrent()
            while wine_process_is_running() != 0 {
                Thread.sleep(forTimeInterval: 0.25)
                let now = CFAbsoluteTimeGetCurrent()
                // Diagnostic heartbeat: 2026-07-03's detach-at-#1 run never
                // triggered despite presents visibly counting — log what this
                // loop actually observes so that can't happen silently again.
                if now - lastHeartbeat > 30 {
                    lastHeartbeat = now
                    logStore.log("detach-wait: presents=\(mythic_get_present_count()) running=\(wine_process_is_running()) elapsed=\(Int(now - pollStart))s")
                }
                // Task #25: the present heuristic is meaningless in desktop
                // mode — ANY child presenting (cube, a game window) trips it
                // mid-session, and later program launches still need the
                // attached-debugger facilities. Desktop sessions stay
                // attached until the desktop exits (or the safety cap).
                let isDesktopSession = getenv("MYTHIC_DESKTOP").map { $0.pointee == 49 } ?? false
                if !isDesktopSession {
                    if presentingSince == nil && mythic_get_present_count() >= 1 {
                        presentingSince = now
                        logStore.log("Game is presenting (#1, splash) — early detach in \(Int(settleAfterFirstPresent))s")
                    }
                    if let t = presentingSince, now - t > settleAfterFirstPresent {
                        logStore.log("Early detach: game presenting and settled", level: .success)
                        break
                    }
                }
                if now - pollStart > maxWait {
                    logStore.log("Wine still running after \(Int(maxWait))s, proceeding with detach", level: .error)
                    break
                }
            }
            let wineElapsed = CFAbsoluteTimeGetCurrent() - pollStart
            logStore.log("Wine finished after \(String(format: "%.1f", wineElapsed))s")

            // Step 5: Resume UI + os_log, give main thread time to recover before detach
            DispatchQueue.main.async {
                ws_log_quiet = 0
                logStore.uiPaused = false
            }
            Thread.sleep(forTimeInterval: 2.0)

            // Step 6: Detach debugger — main thread should have zero accumulated hang time
            logStore.log("Detaching debugger...")
            StikJITHelper.detachDebugger()

            DispatchQueue.main.async { heartbeat.invalidate() }
        }
    }

    private func startWineserver() {
        logStore.log("Starting wineserver...")

        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let winePrefixPath = documentsPath.appendingPathComponent("wine").path

        logStore.log("Wine prefix: \(winePrefixPath)")

        let result = wineserver_start(winePrefixPath)
        if result == 0 {
            logStore.log("Wineserver thread launched successfully", level: .success)
        } else {
            logStore.log("Failed to start wineserver (error: \(result))", level: .error)
        }
    }

    private func startWineProcess() {
        logStore.log("Starting Wine process...")

        if wineserver_is_running() == 0 {
            logStore.log("Wineserver not running! Start it first.", level: .error)
            return
        }

        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let winePrefixPath = documentsPath.appendingPathComponent("wine").path

        // Call synchronously — caller already waited for wineserver to be ready
        let result = wine_process_start(winePrefixPath)
        if result == 0 {
            logStore.log("Wine process thread launched", level: .success)
        } else {
            logStore.log("Failed to start Wine process (error: \(result))", level: .error)
        }
    }

    private func testDualMapping() {
        logStore.log("Testing dual-mapped memory properties...")

        DispatchQueue.global(qos: .userInitiated).async {
            testDualMappingImpl()
        }
    }

    private func testDualMappingImpl() {
        logStore.log("Creating 64KB dual-mapped region...")

        guard let region = jit_region_create(65536) else {
            logStore.log("Failed to create dual-mapped region", level: .error)
            return
        }

        let rwPtr = jit_region_rw_ptr(region)
        let rxPtr = jit_region_rx_ptr(region)
        let size = jit_region_size(region)

        logStore.log("Region created: size=\(size)")
        logStore.log("  RW ptr: \(String(format: "%p", Int(bitPattern: rwPtr)))")
        logStore.log("  RX ptr: \(String(format: "%p", Int(bitPattern: rxPtr)))")

        // Test 1: Write to RW, verify readable from RX
        let testPattern: UInt32 = 0xDEADBEEF
        rwPtr?.assumingMemoryBound(to: UInt32.self).pointee = testPattern
        let readBack = rxPtr?.assumingMemoryBound(to: UInt32.self).pointee

        if readBack == testPattern {
            logStore.log("Dual mapping verified: write to RW visible from RX", level: .success)
        } else {
            logStore.log("Dual mapping FAILED: wrote \(String(format: "0x%X", testPattern)), read \(String(format: "0x%X", readBack ?? 0))", level: .error)
        }

        // Test 2: Verify RW and RX are at different virtual addresses
        if rwPtr != rxPtr {
            logStore.log("Distinct virtual addresses confirmed (RW != RX)", level: .success)
        } else {
            logStore.log("WARNING: RW and RX are at the same address", level: .error)
        }

        jit_region_destroy(region)
        logStore.log("Region destroyed. Dual mapping test complete.")
    }
}

struct SetupGuideView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            List {
                Section("Requirements") {
                    guideRow(
                        icon: "cpu",
                        title: "JIT Compilation",
                        detail: "Required for x86 code translation. On iOS 26, StikDebug must stay attached — assign the 'universal' or 'MeloNX' JIT script to Mythic in StikDebug."
                    )
                    guideRow(
                        icon: "memorychip",
                        title: "Increased Memory Limit",
                        detail: "Raises the Jetsam memory threshold. Included in the app entitlements. If not detected, use GetMoreRam to inject it."
                    )
                    guideRow(
                        icon: "arrow.up.left.and.arrow.down.right",
                        title: "Extended Virtual Addressing",
                        detail: "Expands virtual address space to ~64GB. Required for large games. Must be injected via GetMoreRam (free accounts can't provision this)."
                    )
                }

                Section("Setup Steps") {
                    stepRow(number: 1, text: "Install Mythic via SideStore or Xcode")
                    stepRow(number: 2, text: "Install GetMoreRam and run it to inject memory entitlements into your App ID")
                    stepRow(number: 3, text: "Reinstall Mythic with the same IPA to apply injected entitlements")
                    stepRow(number: 4, text: "In StikDebug, assign the 'universal' JIT script to Mythic and launch it")
                    stepRow(number: 5, text: "Launch Mythic and tap 'Test JIT' to verify")
                }

                Section("About") {
                    Text("Mythic is a proof-of-concept for running x86 Windows games on iOS using FEX-Emu, Wine, and Metal-based graphics translation.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Setup Guide")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func guideRow(icon: String, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(.accentColor)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline).fontWeight(.medium)
                Text(detail).font(.caption).foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    private func stepRow(number: Int, text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.caption).fontWeight(.bold)
                .foregroundColor(.white)
                .frame(width: 22, height: 22)
                .background(Circle().fill(Color.accentColor))
            Text(text)
                .font(.subheadline)
        }
        .padding(.vertical, 2)
    }
}
