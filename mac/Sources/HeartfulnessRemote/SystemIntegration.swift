import AppKit
import ApplicationServices
import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation
import HRCore
import ServiceManagement
import SystemConfiguration

// MARK: - Privacy permissions

enum Permissions {
    static var screenRecording: Bool { CGPreflightScreenCaptureAccess() }

    /// Shows the system prompt the first time; afterwards macOS only lists the app in Settings.
    @discardableResult
    static func requestScreenRecording() -> Bool { CGRequestScreenCaptureAccess() }

    static var accessibility: Bool { AXIsProcessTrusted() }

    /// Shows the system "would like to control this computer" prompt.
    static func requestAccessibility() {
        let options = ["AXTrustedCheckOptionPrompt": true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
    }

    enum Pane: String {
        case screenRecording = "Privacy_ScreenCapture"
        case accessibility = "Privacy_Accessibility"
        case notifications = "Notifications"
    }

    static func open(_ pane: Pane) {
        let urlString: String
        switch pane {
        case .notifications:
            urlString = "x-apple.systempreferences:com.apple.preference.notifications"
        default:
            urlString = "x-apple.systempreferences:com.apple.preference.security?\(pane.rawValue)"
        }
        if let url = URL(string: urlString) { NSWorkspace.shared.open(url) }
    }

    static func openFirewallSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Firewall") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - Firewall

enum FirewallControl {
    /// Reads the firewall state (no admin rights needed). Blocking — call off the main thread.
    static func readState() -> FirewallState {
        let global = run(["--getglobalstate"])
        let stealth = run(["--getstealthmode"])
        return FirewallState(enabled: global.flatMap(FirewallOutputParser.globalState),
                             stealth: stealth.flatMap(FirewallOutputParser.stealthMode))
    }

    private static func run(_ arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: AppleScriptText.socketFilter)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }

    /// Turns on firewall + stealth mode and allows the app and its helper, in one
    /// administrator-privileged step (macOS shows its own password dialog).
    /// Must run on the main thread (NSAppleScript); blocks while the dialog is open.
    @MainActor
    static func enableWithAdminPrompt() -> (ok: Bool, message: String?) {
        var paths = [Bundle.main.bundlePath]
        if let helper = AgentProcess.helperURL?.path { paths.append(helper) }
        let source = AppleScriptText.enableFirewallScript(allowing: paths)
        guard let script = NSAppleScript(source: source) else {
            return (false, "Could not prepare the firewall settings.")
        }
        var errorInfo: NSDictionary?
        _ = script.executeAndReturnError(&errorInfo)
        if let errorInfo {
            let number = (errorInfo[NSAppleScript.errorNumber] as? NSNumber)?.intValue ?? 0
            if number == -128 { return (false, "Cancelled — nothing was changed.") }
            let text = errorInfo[NSAppleScript.errorMessage] as? String ?? "error \(number)"
            Log.app.error("Firewall script failed: \(text, privacy: .public)")
            return (false, "macOS reported a problem: \(text)")
        }
        return (true, nil)
    }
}

// MARK: - Launch at login

enum LoginItem {
    static var status: SMAppService.Status { SMAppService.mainApp.status }
    static var isEnabled: Bool { status == .enabled }

    /// Returns an error message for the owner, or nil on success.
    static func setEnabled(_ enabled: Bool) -> String? {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            if enabled && SMAppService.mainApp.status == .requiresApproval {
                return "macOS needs your OK: in System Settings → General → Login Items, switch on Heartfulness Remote."
            }
            return nil
        } catch {
            Log.app.error("Login item change failed: \(error.localizedDescription, privacy: .public)")
            return "Could not change “Open at login”: \(error.localizedDescription)"
        }
    }

    static func openSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}

// MARK: - Displays

@MainActor
enum DisplayCatalog {
    /// Active, non-mirrored displays (sizes in points). Needs no Screen Recording permission.
    static func current() -> [DisplayInfo] {
        var count: UInt32 = 0
        guard CGGetActiveDisplayList(0, nil, &count) == .success, count > 0 else { return [] }
        var ids = [CGDirectDisplayID](repeating: 0, count: Int(count))
        guard CGGetActiveDisplayList(count, &ids, &count) == .success else { return [] }

        var names: [CGDirectDisplayID: String] = [:]
        for screen in NSScreen.screens {
            let key = NSDeviceDescriptionKey("NSScreenNumber")
            if let number = screen.deviceDescription[key] as? NSNumber {
                names[number.uint32Value] = screen.localizedName
            }
        }

        var result: [DisplayInfo] = []
        for id in ids.prefix(Int(count)) {
            // Skip the secondary members of a mirror set.
            if CGDisplayMirrorsDisplay(id) != 0 { continue }
            let bounds = CGDisplayBounds(id)
            let pointsWide = Int(bounds.width.rounded())
            let pointsHigh = Int(bounds.height.rounded())
            var scale = 1.0
            if let mode = CGDisplayCopyDisplayMode(id), pointsWide > 0 {
                scale = Double(mode.pixelWidth) / Double(pointsWide)
            }
            let primary = CGDisplayIsMain(id) != 0
            let name = names[id] ?? (primary ? "Main display" : "Display \(result.count + 1)")
            result.append(DisplayInfo(id: id, name: name, width: pointsWide, height: pointsHigh,
                                      scale: (scale * 100).rounded() / 100, primary: primary))
        }
        return result
    }
}

// MARK: - QR code

enum QRCode {
    /// A crisp (nearest-neighbour scaled) QR code image, or nil.
    static func image(for text: String, pointSize: CGFloat) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage, output.extent.width > 0 else { return nil }
        let pixelTarget = pointSize * 2   // render for Retina
        let scale = max(1, (pixelTarget / output.extent.width).rounded(.down))
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let context = CIContext(options: [.useSoftwareRenderer: false])
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: pointSize, height: pointSize))
    }
}

// MARK: - Names and paths

enum HostInfo {
    /// The Mac's name as shown in Sharing settings, e.g. "Asha's MacBook Pro".
    static func computerName() -> String {
        if let name = SCDynamicStoreCopyComputerName(nil, nil) as String?, !name.isEmpty {
            return name
        }
        return Host.current().localizedName ?? "Mac"
    }

    /// ~/Library/Application Support/Heartfulness Remote (created with 0700 permissions).
    static func dataDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let dir = base.appendingPathComponent("Heartfulness Remote", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        return dir
    }

    static var appVersion: String {
        let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0"
        return "\(short) (\(build))"
    }
}
