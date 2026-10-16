import AppKit
import SwiftUI

/// Heartfulness Remote host: a menu bar app (LSUIElement) with a dashboard and a setup wizard.
///
/// The dashboard and the wizard are AppKit windows hosting SwiftUI (see WindowManager) rather
/// than SwiftUI `Window` scenes: on macOS 14 a `Window` scene opens by itself at every launch
/// (and so at every login; `defaultLaunchBehavior` is macOS 15+), and both windows must be
/// opened from non-view code (first launch, notifications, the kill-switch hot key).
@main
struct HeartfulnessRemoteApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarPanel()
                .environmentObject(AppModel.shared)
        } label: {
            MenuBarLabel(model: AppModel.shared)
        }
        .menuBarExtraStyle(.window)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        AppMover.ensureSingleInstance { proceed in
            guard proceed else {
                NSApp.terminate(nil)
                return
            }
            // Offers "Move to Applications" when running from Downloads; if accepted, the copy
            // in ~/Applications is opened and this one quits.
            if AppMover.offerMoveIfNeeded() { return }
            AppModel.shared.launch()
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Stop the helper first so it can end the session, write the access log and exit.
        AppModel.shared.prepareForQuit()
        return .terminateLater
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        // Double-clicking the app while it is running opens the dashboard.
        WindowManager.shared.showDashboard()
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
