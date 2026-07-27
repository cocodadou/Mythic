import UIKit

/// Helper to enable JIT via StikDebug/StikJIT URL scheme.
/// Opens StikDebug with an embedded script, polls for CS_DEBUGGED,
/// then allocates JIT memory and detaches the debugger.
enum StikJITHelper {

    /// The JIT script. Edit mythic-jit.js, then run:
    ///   base64 -i app/Mythic/mythic-jit.js | tr -d '\n' | pbcopy
    /// and paste below. TODO: load from bundle resource instead.
    private static let scriptBase64 = "Ly8gTXl0aGljIEpJVCBTY3JpcHQgZm9yIFN0aWtEZWJ1ZwovLyBIYW5kbGVzIEJSSyAjMHhmMDBkICh1bml2ZXJzYWwgcHJvdG9jb2wpIHdpdGggeDE2LWJhc2VkIGNvbW1hbmQgZGlzcGF0Y2gKLy8gQWR2YW5jZXMgUEMgcGFzdCBBTEwgQlJLIGluc3RydWN0aW9ucyB0byBwcmV2ZW50IGluZmluaXRlIGxvb3BzCgpmdW5jdGlvbiBsaXR0bGVFbmRpYW5IZXhTdHJpbmdUb051bWJlcihoZXhTdHIpIHsKICAgIGNvbnN0IGJ5dGVzID0gW107CiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGhleFN0ci5sZW5ndGg7IGkgKz0gMikgewogICAgICAgIGJ5dGVzLnB1c2gocGFyc2VJbnQoaGV4U3RyLnN1YnN0cihpLCAyKSwgMTYpKTsKICAgIH0KICAgIGxldCBudW0gPSAwbjsKICAgIGZvciAobGV0IGkgPSA3OyBpID49IDA7IGktLSkgewogICAgICAgIG51bSA9IChudW0gPDwgOG4pIHwgQmlnSW50KGJ5dGVzW2ldIHx8IDApOwogICAgfQogICAgcmV0dXJuIG51bTsKfQoKZnVuY3Rpb24gbnVtYmVyVG9MaXR0bGVFbmRpYW5IZXhTdHJpbmcobnVtKSB7CiAgICBjb25zdCBieXRlcyA9IFtdOwogICAgZm9yIChsZXQgaSA9IDA7IGkgPCA4OyBpKyspIHsKICAgICAgICBieXRlcy5wdXNoKE51bWJlcihudW0gJiAweEZGbikpOwogICAgICAgIG51bSA+Pj0gOG47CiAgICB9CiAgICByZXR1cm4gYnl0ZXMubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7Cn0KCmZ1bmN0aW9uIGxpdHRsZUVuZGlhbkhleFRvVTMyKGhleFN0cikgewogICAgcmV0dXJuIHBhcnNlSW50KGhleFN0ci5tYXRjaCgvLi4vZykucmV2ZXJzZSgpLmpvaW4oJycpLCAxNik7Cn0KCmZ1bmN0aW9uIGV4dHJhY3RCcmtJbW1lZGlhdGUodTMyKSB7CiAgICByZXR1cm4gKHUzMiA+PiA1KSAmIDB4RkZGRjsKfQoKbGV0IHBpZCA9IGdldF9waWQoKTsKbG9nKGBNeXRoaWMgSklUOiBwaWQgPSAke3BpZH1gKTsKbGV0IGF0dGFjaFJlc3BvbnNlID0gc2VuZF9jb21tYW5kKGB2QXR0YWNoOyR7cGlkLnRvU3RyaW5nKDE2KX1gKTsKbG9nKGBNeXRoaWMgSklUOiBhdHRhY2hlZCA9ICR7YXR0YWNoUmVzcG9uc2V9YCk7CgpsZXQgZGV0YWNoZWQgPSBmYWxzZTsKCndoaWxlICghZGV0YWNoZWQpIHsKICAgIGxldCBicmtSZXNwb25zZSA9IHNlbmRfY29tbWFuZChgY2ApOwoKICAgIGxldCB0aWRNYXRjaCA9IC9UWzAtOWEtZl0rdGhyZWFkOig/PHRpZD5bMC05YS1mXSspOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgdGlkID0gdGlkTWF0Y2ggPyB0aWRNYXRjaC5ncm91cHNbJ3RpZCddIDogbnVsbDsKICAgIGxldCBwY01hdGNoID0gLzIwOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgcGMgPSBwY01hdGNoID8gcGNNYXRjaC5ncm91cHNbJ3JlZyddIDogbnVsbDsKICAgIGxldCB4MTZNYXRjaCA9IC8xMDooPzxyZWc+WzAtOWEtZl17MTZ9KTsvLmV4ZWMoYnJrUmVzcG9uc2UpOwogICAgbGV0IHgxNiA9IHgxNk1hdGNoID8geDE2TWF0Y2guZ3JvdXBzWydyZWcnXSA6IG51bGw7CgogICAgaWYgKCF0aWQgfHwgIXBjIHx8ICF4MTYpIHsKICAgICAgICBsb2coYE15dGhpYyBKSVQ6IGZhaWxlZCB0byBwYXJzZSwgY29udGludWluZ2ApOwogICAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIGxldCBwY051bSA9IGxpdHRsZUVuZGlhbkhleFN0cmluZ1RvTnVtYmVyKHBjKTsKCiAgICBsZXQgaW5zdHJIZXggPSBzZW5kX2NvbW1hbmQoYG0ke3BjTnVtLnRvU3RyaW5nKDE2KX0sNGApOwogICAgbGV0IGluc3RyVTMyID0gbGl0dGxlRW5kaWFuSGV4VG9VMzIoaW5zdHJIZXgpOwogICAgbGV0IGJya0ltbSA9IGV4dHJhY3RCcmtJbW1lZGlhdGUoaW5zdHJVMzIpOwoKICAgIC8vIEFMV0FZUyBhZHZhbmNlIFBDIHBhc3QgQlJLIHRvIHByZXZlbnQgaW5maW5pdGUgbG9vcAogICAgbGV0IHBjUGx1czQgPSBudW1iZXJUb0xpdHRsZUVuZGlhbkhleFN0cmluZyhwY051bSArIDRuKTsKICAgIHNlbmRfY29tbWFuZChgUDIwPSR7cGNQbHVzNH07dGhyZWFkOiR7dGlkfTtgKTsKCiAgICAvLyBTa2lwIHVua25vd24gQlJLIGltbWVkaWF0ZXMgKFBDIGFscmVhZHkgYWR2YW5jZWQpCiAgICBpZiAoYnJrSW1tICE9PSAweGYwMGQgJiYgYnJrSW1tICE9PSAweDY5KSB7CiAgICAgICAgLy8gU2V0IHgwPTAgKGZhaWx1cmUvc2tpcCBpbmRpY2F0b3IpIHNvIGFwcCdzIFNJR1RSQVAgZmFsbGJhY2sgd29ya3MKICAgICAgICBzZW5kX2NvbW1hbmQoYFAwPSR7bnVtYmVyVG9MaXR0bGVFbmRpYW5IZXhTdHJpbmcoMG4pfTt0aHJlYWQ6JHt0aWR9O2ApOwogICAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIGxvZyhgTXl0aGljIEpJVDogQlJLICMweCR7YnJrSW1tLnRvU3RyaW5nKDE2KX1gKTsKCiAgICAvLyBQYXJzZSB4MCBhbmQgeDEKICAgIGxldCB4ME1hdGNoID0gLzAwOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgeDFNYXRjaCA9IC8wMTooPzxyZWc+WzAtOWEtZl17MTZ9KTsvLmV4ZWMoYnJrUmVzcG9uc2UpOwogICAgbGV0IHgwID0geDBNYXRjaCA/IGxpdHRsZUVuZGlhbkhleFN0cmluZ1RvTnVtYmVyKHgwTWF0Y2guZ3JvdXBzWydyZWcnXSkgOiAwbjsKICAgIGxldCB4MSA9IHgxTWF0Y2ggPyBsaXR0bGVFbmRpYW5IZXhTdHJpbmdUb051bWJlcih4MU1hdGNoLmdyb3Vwc1sncmVnJ10pIDogMG47CiAgICBsZXQgeDE2TnVtID0gbGl0dGxlRW5kaWFuSGV4U3RyaW5nVG9OdW1iZXIoeDE2KTsKCiAgICBpZiAoYnJrSW1tID09PSAweGYwMGQpIHsKICAgICAgICBsb2coYE15dGhpYyBKSVQ6IHgxNiA9ICR7eDE2TnVtfWApOwoKICAgICAgICBpZiAoeDE2TnVtID09PSAwbikgewogICAgICAgICAgICAvLyBDTURfREVUQUNICiAgICAgICAgICAgIGxvZyhgTXl0aGljIEpJVDogZGV0YWNoYCk7CiAgICAgICAgICAgIHNlbmRfY29tbWFuZChgRGApOwogICAgICAgICAgICBkZXRhY2hlZCA9IHRydWU7CgogICAgICAgIH0gZWxzZSBpZiAoeDE2TnVtID09PSAxbikgewogICAgICAgICAgICAvLyBDTURfUFJFUEFSRV9SRUdJT04KICAgICAgICAgICAgbG9nKGBNeXRoaWMgSklUOiBwcmVwYXJlIGFkZHI9MHgke3gwLnRvU3RyaW5nKDE2KX0gc2l6ZT0weCR7eDEudG9TdHJpbmcoMTYpfWApOwoKICAgICAgICAgICAgbGV0IGFkZHIgPSB4MDsKICAgICAgICAgICAgaWYgKHgwID09PSAwbiAmJiB4MSAhPT0gMG4pIHsKICAgICAgICAgICAgICAgIGxldCBhbGxvY1Jlc3AgPSBzZW5kX2NvbW1hbmQoYF9NJHt4MS50b1N0cmluZygxNil9LHJ4YCk7CiAgICAgICAgICAgICAgICBpZiAoYWxsb2NSZXNwICYmIGFsbG9jUmVzcC5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICAgICAgYWRkciA9IEJpZ0ludChgMHgke2FsbG9jUmVzcH1gKTsKICAgICAgICAgICAgICAgICAgICBsb2coYE15dGhpYyBKSVQ6IGFsbG9jYXRlZCBhdCAweCR7YWRkci50b1N0cmluZygxNil9YCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIGlmIChhZGRyICE9PSAwbiAmJiB4MSAhPT0gMG4pIHsKICAgICAgICAgICAgICAgIGxldCBwcmVwUmVzcCA9IHByZXBhcmVfbWVtb3J5X3JlZ2lvbihhZGRyLCB4MSk7CiAgICAgICAgICAgICAgICBsb2coYE15dGhpYyBKSVQ6IHByZXBhcmVkID0gJHtwcmVwUmVzcH1gKTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgc2VuZF9jb21tYW5kKGBQMD0ke251bWJlclRvTGl0dGxlRW5kaWFuSGV4U3RyaW5nKGFkZHIpfTt0aHJlYWQ6JHt0aWR9O2ApOwoKICAgICAgICB9IGVsc2UgaWYgKHgxNk51bSA9PT0gM24pIHsKICAgICAgICAgICAgLy8gQ01EX01BUF9QQUdFX1pFUk86IE1hcCBhIHBhZ2UgYXQgYWRkcmVzcyAwIHdpdGggVEVCIGRhdGEuCiAgICAgICAgICAgIC8vIHgwID0gVEVCIGFkZHJlc3MsIHgxID0gc2l6ZSAoMHg0MDAwID0gMTZLQiBpT1MgcGFnZSkKICAgICAgICAgICAgLy8gVGhlIGFwcCBjYW4ndCBtYXAgcGFnZSAwIGl0c2VsZiAoa2VybmVsIHJlZnVzZXMpLiBUaGUgZGVidWdnZXIKICAgICAgICAgICAgLy8gbWF5IGhhdmUgZGlmZmVyZW50IHByaXZpbGVnZXMgdG8gY3JlYXRlIHRoaXMgbWFwcGluZy4KICAgICAgICAgICAgbG9nKGBNeXRoaWMgSklUOiBtYXAgcGFnZSB6ZXJvLCBURUI9MHgke3gwLnRvU3RyaW5nKDE2KX0gc2l6ZT0weCR7eDEudG9TdHJpbmcoMTYpfWApOwoKICAgICAgICAgICAgbGV0IHN1Y2Nlc3MgPSAwbjsKCiAgICAgICAgICAgIC8vIFRyeSBhbGxvY2F0aW5nIFJXIG1lbW9yeSBhdCBhZGRyZXNzIDAgdmlhIF9NIHdpdGggZml4ZWQgYWRkcmVzcwogICAgICAgICAgICAvLyBTdGlrRGVidWcncyBfTSBjb21tYW5kOiBfTTxzaXplPiw8cGVybXM+IOKAlCBidXQgZG9lc24ndCBzdXBwb3J0IGZpeGVkIGFkZHIKICAgICAgICAgICAgLy8gVHJ5IEdEQiBtZW1vcnkgYWxsb2NhdGlvbjogbW1hcCB2aWEgdGhlIGRlYnVnZ2VyJ3MgdGFzayBwb3J0CiAgICAgICAgICAgIC8vIFVzZSB2Q29udCBvciBkaXJlY3QgTWFjaCBjYWxscyBpZiBhdmFpbGFibGUKCiAgICAgICAgICAgIC8vIEFwcHJvYWNoIDE6IFRyeSB3cml0aW5nIFRFQiBkYXRhIHRvIGFkZHJlc3MgMCBkaXJlY3RseS4KICAgICAgICAgICAgLy8gSWYgdGhlIGhhcmR3YXJlIHplcm8gcGFnZSBpcyB3cml0YWJsZSB2aWEgdGhlIGRlYnVnZ2VyLCB0aGlzIHdvcmtzLgogICAgICAgICAgICBpZiAoeDAgIT09IDBuICYmIHgxICE9PSAwbikgewogICAgICAgICAgICAgICAgLy8gUmVhZCBURUIgZGF0YSBmcm9tIHRoZSBhcHAncyBtZW1vcnkKICAgICAgICAgICAgICAgIGxldCB0ZWJQYWdlID0geDAgJiB+MHgzRkZGbjsgIC8vIGFsaWduIHRvIDE2S0IgcGFnZQogICAgICAgICAgICAgICAgbGV0IHRlYk9mZiA9IHgwIC0gdGViUGFnZTsKCiAgICAgICAgICAgICAgICAvLyBUcnkgdG8gd3JpdGUgVEVCIGRhdGEgYXQgYWRkcmVzcyAwIHZpYSBHREIgTSBjb21tYW5kCiAgICAgICAgICAgICAgICAvLyBSZWFkIDI1NiBieXRlcyBmcm9tIFRFQiAoZW5vdWdoIGZvciBQRUIgcG9pbnRlciBhdCBvZmZzZXQgMHg2MCkKICAgICAgICAgICAgICAgIGxldCB0ZWJEYXRhID0gc2VuZF9jb21tYW5kKGBtJHt4MC50b1N0cmluZygxNil9LDEwMGApOwogICAgICAgICAgICAgICAgaWYgKHRlYkRhdGEgJiYgdGViRGF0YS5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICAgICAgLy8gV3JpdGUgaXQgdG8gYWRkcmVzcyAwK3RlYk9mZgogICAgICAgICAgICAgICAgICAgIGxldCB3cml0ZVJlc3AgPSBzZW5kX2NvbW1hbmQoYE0ke3RlYk9mZi50b1N0cmluZygxNil9LCR7KHRlYkRhdGEubGVuZ3RoLzIpLnRvU3RyaW5nKDE2KX06JHt0ZWJEYXRhfWApOwogICAgICAgICAgICAgICAgICAgIGxvZyhgTXl0aGljIEpJVDogd3JpdGUgVEVCIHRvIHBhZ2UwIG9mZnNldCAweCR7dGViT2ZmLnRvU3RyaW5nKDE2KX06ICR7d3JpdGVSZXNwfWApOwogICAgICAgICAgICAgICAgICAgIGlmICh3cml0ZVJlc3AgPT09ICdPSycpIHsKICAgICAgICAgICAgICAgICAgICAgICAgc3VjY2VzcyA9IDFuOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgc2VuZF9jb21tYW5kKGBQMD0ke251bWJlclRvTGl0dGxlRW5kaWFuSGV4U3RyaW5nKHN1Y2Nlc3MpfTt0aHJlYWQ6JHt0aWR9O2ApOwogICAgICAgIH0KCiAgICB9IGVsc2UgaWYgKGJya0ltbSA9PT0gMHg2OSkgewogICAgICAgIC8vIExlZ2FjeSBwcm90b2NvbAogICAgICAgIGxvZyhgTXl0aGljIEpJVDogbGVnYWN5IEJSSyAweDY5LCB4MD0weCR7eDAudG9TdHJpbmcoMTYpfWApOwogICAgICAgIGlmICh4MCAhPT0gMG4pIHsKICAgICAgICAgICAgcHJlcGFyZV9tZW1vcnlfcmVnaW9uKHgwLCB4MCk7CiAgICAgICAgfQogICAgICAgIHNlbmRfY29tbWFuZChgUDA9JHtudW1iZXJUb0xpdHRsZUVuZGlhbkhleFN0cmluZyh4MCl9O3RocmVhZDoke3RpZH07YCk7CiAgICB9Cn0K"

    /// Load script from mythic-jit.js file next to the binary (development convenience).
    /// Falls back to the embedded base64 above for release builds.
    private static var resolvedScriptBase64: String {
        // Try loading from bundle first (if added to Copy Bundle Resources)
        if let url = Bundle.main.url(forResource: "mythic-jit", withExtension: "js"),
           let data = try? Data(contentsOf: url) {
            return data.base64EncodedString()
        }
        return scriptBase64
    }

    /// Check if StikDebug or StikJIT is available by trying to open their URL.
    static var isAvailable: Bool {
        guard let url = URL(string: "stikjit://enable-jit") else { return false }
        return UIApplication.shared.canOpenURL(url)
    }

    /// Open StikDebug with our JIT script embedded in the URL.
    /// StikDebug will attach to our process and run the script.
    static func enableJIT(completion: @escaping (Bool) -> Void) {
        let bundleId = Bundle.main.bundleIdentifier ?? "com.mythic.emulator"

        // Build the URL with script data
        let scriptData = resolvedScriptBase64.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        let urlString = "stikjit://enable-jit?bundle-id=\(bundleId)&script-data=\(scriptData)"

        guard let url = URL(string: urlString) else {
            LogStore.shared.log("Failed to build StikJIT URL", level: .error)
            completion(false)
            return
        }

        LogStore.shared.log("Opening StikDebug to enable JIT...")

        UIApplication.shared.open(url, options: [:]) { success in
            if !success {
                LogStore.shared.log("Failed to open StikDebug. Is it installed?", level: .error)
                completion(false)
                return
            }

            // Poll for CS_DEBUGGED flag
            pollForJIT(completion: completion)
        }
    }

    /// Poll every 0.5s until CS_DEBUGGED is set, then call completion.
    private static func pollForJIT(completion: @escaping (Bool) -> Void) {
        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { timer in
            if jit_check_debugged() {
                timer.invalidate()
                LogStore.shared.log("JIT enabled! (CS_DEBUGGED set)", level: .success)
                completion(true)
            }
        }
    }

    /// Allocate a JIT memory pool via BRK #0xf00d, then detach the debugger.
    /// Call this after CS_DEBUGGED is confirmed.
    /// Returns the allocated RX base address and RW mapping, or nil on failure.
    static func allocateAndDetach(poolSize: Int = 128 * 1024 * 1024) -> (rx: UnsafeMutableRawPointer, rw: UnsafeMutableRawPointer, size: Int)? {
        guard let result = allocatePool(poolSize: poolSize) else { return nil }
        // Don't detach yet — Wine needs the debugger to prepare PE DLL code pages.
        // Detach will happen later via detachDebugger().
        return result
    }

    /// Allocate a JIT memory pool via BRK #0xf00d WITHOUT detaching the debugger.
    /// The debugger stays attached so Wine can use BRK to prepare PE code pages.
    static func allocatePool(poolSize: Int = 128 * 1024 * 1024) -> (rx: UnsafeMutableRawPointer, rw: UnsafeMutableRawPointer, size: Int)? {
        LogStore.shared.log("Allocating \(poolSize / 1024 / 1024)MB JIT pool via debugger...")

        // iOS-Mythic: FEX's dispatcher emit has a position-dependent encoding
        // bug — only works when the JIT pool lands at a high enough address
        // (empirically ≥ 0x119000000, so dispatcher at +0x7ffc130 has top byte
        // 0x12). When iOS allocates 0x114-0x117xxx the dispatcher's literal-
        // pool fixups silently break and execution branches to zero memory
        // before the first compiled block runs. Pre-claim ~96MB of low address
        // space to push the next ANYWHERE allocation up.
        //
        // We keep these allocations alive for the lifetime of the process —
        // freeing them could let iOS reuse them and cause aliasing issues.
        var pinChunks: [vm_address_t] = []
        let chunkSize = 16 * 1024 * 1024  // 16 MB per chunk
        // Pin until the allocation frontier crosses the mode-A threshold
        // (0x119000000) instead of a fixed 96MB. A fixed count loses the
        // ASLR lottery whenever the base slide is low (observed 2026-07-03:
        // 6 chunks ended at 0x118790000, pool landed 8.4MB short of the
        // threshold and the run fast-failed). vm_allocate is zero-fill
        // reserve-only, so extra chunks don't add resident footprint.
        // The BAD POOL check below stays as the safety net for non-
        // sequential placements.
        let pinTarget: vm_address_t = 0x119000000
        let maxChunks = 32                 // safety cap (512 MB of reservation)
        for i in 0..<maxChunks {
            var addr: vm_address_t = 0
            let kr = vm_allocate(mach_task_self_, &addr, vm_size_t(chunkSize), VM_FLAGS_ANYWHERE)
            if kr == KERN_SUCCESS {
                pinChunks.append(addr)
                LogStore.shared.log(String(format: "JIT-pool pin chunk %d at 0x%lx (16MB)", i, Int(addr)))
                if addr + vm_address_t(chunkSize) >= pinTarget { break }
            } else {
                LogStore.shared.log("JIT-pool pin chunk \(i) FAILED kr=\(kr)", level: .error)
                break
            }
        }

        // Ask debugger to allocate RX pages (x0=0 triggers _M allocation).
        // With pin chunks claimed, this should land at a higher address.
        //
        // Two placement constraints (violating either bricks the session):
        // - LOW BOUND: FEX has a position-dependent emit bug below
        //   0x119000000 (mode A: dispatcher branches to zero memory before
        //   block 0 runs; higher-address mode B is runtime-patched in
        //   signal_arm64_ios.c init_syscall_frame).
        // - GUEST WINDOW (ml78, 2026-07-13): with the 896MB pool the kernel
        //   often places the region at 0x7000000000 — inside the guest
        //   x86-64 64GB window [0x70,0x80)G where Wine packs PE images and
        //   the fault handlers classify PCs as guest addresses. Executing
        //   pool code there hangs the first pool call silently (black
        //   screen / wallpaper-only desktop).
        // Reject bad placements and re-roll: a bad region is freed when the
        // kernel allows, otherwise kept alive as a pin — either way the next
        // jit26 pick must land elsewhere.
        let goodLow = 0x119000000
        let guestLo = 0x7000000000
        let guestHi = 0x8000000000
        var rxPtrOpt: UnsafeMutableRawPointer? = nil
        for attempt in 0..<3 {
            guard let p = jit26_prepare_region(nil, poolSize), p != UnsafeMutableRawPointer(bitPattern: 0) else {
                LogStore.shared.log("Debugger failed to allocate RX memory (attempt \(attempt))", level: .error)
                break
            }
            let a = Int(bitPattern: p)
            let inGuestWindow = a + poolSize > guestLo && a < guestHi
            if a >= goodLow && !inGuestWindow {
                rxPtrOpt = p
                break
            }
            LogStore.shared.log(String(format: "BAD POOL placement 0x%lx (%@) — re-rolling (attempt %d)",
                                       a, a < goodLow ? "mode A low" : "guest 64G window",
                                       attempt), level: .error)
            let dkr = vm_deallocate(mach_task_self_, vm_address_t(a), vm_size_t(poolSize))
            LogStore.shared.log(dkr == KERN_SUCCESS
                ? "  bad region freed"
                : "  bad region kept as pin (vm_deallocate kr=\(dkr))")
        }
        guard let rxPtr = rxPtrOpt else {
            LogStore.shared.log("BAD POOL: no valid placement after retries. Killing in 10s — please relaunch.", level: .error)
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 10) {
                LogStore.shared.log("BAD POOL — exiting now. Relaunch the app.", level: .error)
                exit(0)
            }
            return nil
        }
        let rxAddr = Int(bitPattern: rxPtr)
        LogStore.shared.log("RX pool at \(String(format: "%p", rxAddr))")

        // Create RW mapping via vm_remap
        var rwAddr: vm_address_t = 0
        var curProt: vm_prot_t = 0
        var maxProt: vm_prot_t = 0

        // task #35: place the RW alias BELOW the 64GB carveout floor.
        // With VM_FLAGS_ANYWHERE the kernel picks the first free address above
        // the GPU carveout [64G,448G) — which is 0x7000000000 exactly. That is
        // the base of a 16GB jumbo slot, so this 896MB data-only mapping was
        // sterilizing a whole slot that CEF's PartitionAlloc needs. The top
        // window [448G,512G) holds only four such slots and CEF wants at least
        // four pools, so we cannot afford to spend one on ourselves.
        // Data-only (never executed — exec always goes through the RX alias),
        // so placement is unconstrained; fall back to ANYWHERE if all candidates
        // are taken, which restores the previous behaviour exactly.
        // ml91: six hand-picked candidates (8/12/16/24/32/48G) ALL failed —
        // sub-64G is far more crowded than assumed. Sweep the whole region on a
        // 1GB stride instead of guessing. Each failed vm_remap(FIXED) is cheap,
        // so ~58 probes at startup costs nothing and finds any real hole.
        // ml92 measured the real map: there is NO sub-64G space at all. The only
        // "free" region down there (0..0x102454000) is __PAGEZERO, and 4G-64G is
        // fully reserved (malloc xzone) — 58 probes on a 1GB stride found nothing.
        // Usable VA is exactly one ~63GB window, 0x7038000000..0x7fffdf0000.
        //
        // That window holds four 16GB-aligned slots (448/464/480/496G) and CEF's
        // PartitionAlloc wants one pool per slot. Landing here at 0x7000000000
        // spends the 448G slot on an 896MB mapping. Slot 496G is ALREADY ruined
        // by Wine furniture (PE images at ~0x7e874c0000 = 505.8G), so parking at
        // the very top costs nothing that isn't already lost and hands 448G back
        // to PartitionAlloc intact.
        // ml91/ml92/ml93: relocating this alias was tried and REVERTED. The map
        // says usable VA is a single ~63GB window (0x7038000000..0x7fffdf0000);
        // sub-64G is __PAGEZERO plus a fully-reserved 4G-64G band, so 58 probes
        // on a 1GB stride found nothing (ml92). Parking at the top of space
        // instead (0x7fc8000000) DID place, but Wine allocates its furniture
        // top-down — the TEB landed 1.25MB below us at 0x7fc7ec0000, pool copies
        // came out zero-filled, and libarm64ecfex died on 8 exec faults before
        // CEF was even reached (ml93). There is nowhere to put an 896MB mapping
        // that does not cost either a 16GB PartitionAlloc slot or Wine's own
        // furniture. The kernel pick (0x7000000000, base of the window) is the
        // least harmful: it spends the 448G slot but leaves the top — where Wine
        // clusters — alone.
        // ml96 census: CEF needs THREE 16GB pools (48GB), not the 144GB a naive
        // sum suggested — #3/#4/#5 are one pool re-rolling its hint, and the two
        // 32GB requests are that same pool over-reserving for 16GB ALIGNMENT.
        // 48GB fits in the 63GB window, so the third pool fails only because no
        // 16GB-ALIGNED slot is left: 464G and 480G are taken, 496G is broken by
        // Wine furniture, and 448G is spent on this 896MB alias.
        //
        // Freeing 448G should let pool 3 land. ml93 tried that and failed by
        // parking at 0x7fc8000000 — the extreme top, exactly where Wine
        // allocates its furniture top-down (the TEB landed 1.25MB below us and
        // pool copies came back zeroed). The map says 0x7c00000000..0x7e874c0000
        // is free, so take the BOTTOM of the already-broken 496G slot instead
        // and leave the top for Wine.
        // DO NOT relocate this alias without new evidence. Three placements were
        // measured against the default kernel pick (0x7000000000, which the
        // kernel picks because it is the first free address above the GPU
        // carveout):
        //   0x7000000000 (default)  ml94=8, ml96=1  exec faults, reaches libcef
        //   0x7fc8000000 (top)      ml93=8          exec faults, dies before CEF
        //   0x7c00000000 (496G)     ml97=16, ml98=16 exec faults, dies before CEF
        // Same fault class in every case (pool page loses content/exec, on a
        // recycled range) — relocation makes an EXISTING intermittent bug worse
        // rather than introducing a new one. Two mechanisms were proposed and
        // BOTH disproven: Wine furniture collision (ml93) and the reclaim-recover
        // band claiming the alias (ml97; the band exclusion landed in
        // signal_arm64_ios.c and did NOT change the count). Whatever couples the
        // alias base to pool stability is still unidentified.
        //
        // Cost of staying here: the alias occupies the base of the 448G slot, so
        // PartitionAlloc gets only two of the three 16GB-aligned pools it needs
        // (see the ml96 [jumbo#N] census). Freeing that slot is worth doing —
        // but by moving WINE's furniture out of 496G, not by moving this.
        rwAddr = 0
        let kr1 = vm_remap(
            mach_task_self_,
            &rwAddr,
            vm_size_t(poolSize),
            0,
            VM_FLAGS_ANYWHERE,
            mach_task_self_,
            vm_address_t(bitPattern: rxPtr),
            0, // copy = false
            &curProt,
            &maxProt,
            VM_INHERIT_NONE
        )

        guard kr1 == KERN_SUCCESS else {
            LogStore.shared.log("vm_remap failed: \(kr1)", level: .error)
            return nil
        }

        // Set RW protection
        let kr2 = vm_protect(mach_task_self_, rwAddr, vm_size_t(poolSize), 0, VM_PROT_READ | VM_PROT_WRITE)
        guard kr2 == KERN_SUCCESS else {
            LogStore.shared.log("vm_protect(RW) failed: \(kr2)", level: .error)
            vm_deallocate(mach_task_self_, rwAddr, vm_size_t(poolSize))
            return nil
        }

        let rwPtr = UnsafeMutableRawPointer(bitPattern: rwAddr)!
        LogStore.shared.log("RW mapping at \(String(format: "%p", Int(bitPattern: rwPtr)))")
        LogStore.shared.log("JIT pool ready (debugger still attached).", level: .success)

        return (rx: rxPtr, rw: rwPtr, size: poolSize)
    }

    /// Detach the debugger. Call this after Wine is done loading PE DLLs.
    static func detachDebugger() {
        LogStore.shared.log("Detaching debugger...")
        jit26_detach()
        // task #34: signal in-process waiters (share-probe poller). CS_DEBUGGED
        // is sticky post-detach, so an env flag is the reliable signal.
        setenv("MYTHIC_DETACHED", "1", 1)
        LogStore.shared.log("Debugger detached.", level: .success)
    }
}
