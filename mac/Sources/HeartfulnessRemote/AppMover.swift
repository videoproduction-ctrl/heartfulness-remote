import AppKit
import Darwin
import Foundation
import HRCore

/// First-launch housekeeping for the downloaded app:
///  * offers to move itself into ~/Applications (clearing the download quarantine on the copy)
///  * makes sure only one copy runs at a time
@MainActor
enum AppMover {
    /// Returns true if the app is relaunching from the new location and this copy should quit.
    static func offerMoveIfNeeded() -> Bool {
        let bundleURL = Bundle.main.bundleURL
        guard bundleURL.pathExtension == "app" else { return false }   // `swift run` etc.
        let home = NSHomeDirectory()
        if AppPlacement.isInApplicationsFolder(bundlePath: bundleURL.path, homeDirectory: home) { return false }
        if UserDefaults.standard.bool(forKey: "hr.dontOfferMove") { return false }

        let alert = NSAlert()
        alert.messageText = "Move Heartfulness Remote to your Applications folder?"
        alert.informativeText = "It is running from “\(bundleURL.deletingLastPathComponent().lastPathComponent)”. To start automatically when your Mac starts and to keep working after you empty Downloads, it needs to live in Applications. This takes a second; the app will reopen by itself."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Move to Applications")
        alert.addButton(withTitle: "Not Now")
        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = "Don't ask again"
        NSApp.activate()
        let response = alert.runModal()
        if alert.suppressionButton?.state == .on {
            UserDefaults.standard.set(true, forKey: "hr.dontOfferMove")
        }
        guard response == .alertFirstButtonReturn else { return false }

        let destinationPath = AppPlacement.destination(bundleName: bundleURL.lastPathComponent, homeDirectory: home)
        let destination = URL(fileURLWithPath: destinationPath)
        do {
            try copyApp(from: bundleURL, to: destination)
        } catch {
            Log.app.error("Move to Applications failed: \(error.localizedDescription, privacy: .public)")
            let failure = NSAlert()
            failure.messageText = "Couldn't move the app"
            failure.informativeText = "Please drag “Heartfulness Remote” into the Applications folder yourself, then open it from there.\n\n(\(error.localizedDescription))"
            failure.runModal()
            return false
        }

        relaunch(from: destination)
        return true
    }

    private static func copyApp(from source: URL, to destination: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        if fm.fileExists(atPath: destination.path) {
            // Replace an older copy (moved to the Trash so nothing is lost by accident).
            do {
                try fm.trashItem(at: destination, resultingItemURL: nil)
            } catch {
                try fm.removeItem(at: destination)
            }
        }
        try fm.copyItem(at: source, to: destination)
        removeQuarantine(at: destination)
    }

    /// Removes com.apple.quarantine from every file in the copied bundle.
    static func removeQuarantine(at url: URL) {
        let name = "com.apple.quarantine"
        _ = removexattr(url.path, name, XATTR_NOFOLLOW)
        guard let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil) else { return }
        for case let item as URL in enumerator {
            _ = removexattr(item.path, name, XATTR_NOFOLLOW)
        }
    }

    private static func relaunch(from destination: URL) {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: destination, configuration: configuration) { _, error in
            if let error {
                Log.app.error("Relaunch failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        // Give LaunchServices a moment to start the new copy, then quit this one.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            MainActor.assumeIsolated {
                NSApp.terminate(nil)
            }
        }
    }

    /// If another copy is already running, waits briefly (it may be the old copy quitting
    /// after "Move to Applications"), then either continues or hands over and quits.
    /// Calls `completion(true)` if this instance should carry on starting up.
    static func ensureSingleInstance(completion: @escaping @MainActor (Bool) -> Void) {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            completion(true)
            return
        }
        let me = NSRunningApplication.current.processIdentifier
        Task { @MainActor in
            for _ in 0..<20 {
                let others = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
                    .filter { $0.processIdentifier != me && !$0.isTerminated }
                if others.isEmpty {
                    completion(true)
                    return
                }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
            let others = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
                .filter { $0.processIdentifier != me && !$0.isTerminated }
            if let other = others.first {
                Log.app.notice("Another copy is already running; handing over")
                _ = other.activate(options: [])
                completion(false)
            } else {
                completion(true)
            }
        }
    }
}
