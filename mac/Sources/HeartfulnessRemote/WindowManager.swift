import AppKit
import SwiftUI

enum DashboardSection: String, CaseIterable, Identifiable, Hashable {
    case status
    case devices
    case approvals
    case log
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .status: return "Status"
        case .devices: return "Devices"
        case .approvals: return "Approvals"
        case .log: return "Access Log"
        case .settings: return "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .status: return "dot.radiowaves.left.and.right"
        case .devices: return "laptopcomputer.and.iphone"
        case .approvals: return "checkmark.shield"
        case .log: return "list.bullet.rectangle"
        case .settings: return "gearshape"
        }
    }
}

enum WizardStep: Int, CaseIterable, Identifiable, Hashable {
    case welcome
    case server
    case screenRecording
    case accessibility
    case notifications
    case firewall
    case launchAtLogin
    case pairPhone
    case done

    var id: Int { rawValue }
}

/// The dashboard and setup wizard are plain AppKit windows hosting SwiftUI, so they can be
/// opened from anywhere (menu, notifications, hot key, first launch) and never open by
/// themselves at login — which a SwiftUI `Window` scene would do on macOS 14.
@MainActor
final class WindowManager: NSObject, NSWindowDelegate {
    static let shared = WindowManager()

    private var dashboardWindow: NSWindow?
    private var wizardWindow: NSWindow?

    func showDashboard(section: DashboardSection? = nil) {
        let model = AppModel.shared
        if let section { model.dashboardSection = section }
        if dashboardWindow == nil {
            let root = DashboardView().environmentObject(model)
            let controller = NSHostingController(rootView: root)
            let window = NSWindow(contentViewController: controller)
            window.title = "Heartfulness Remote"
            window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            window.setContentSize(NSSize(width: 940, height: 640))
            window.contentMinSize = NSSize(width: 780, height: 520)
            window.isReleasedWhenClosed = false
            window.delegate = self
            window.center()
            window.setFrameAutosaveName("HeartfulnessDashboard")
            dashboardWindow = window
        }
        present(dashboardWindow)
    }

    /// Opens the wizard with the given steps (all of them for first-run setup, or only the
    /// steps that need attention, e.g. after an update reset a permission).
    func showWizard(steps: [WizardStep] = WizardStep.allCases, notice: String? = nil) {
        let model = AppModel.shared
        wizardWindow?.close()
        let root = SetupWizardView(steps: steps.isEmpty ? WizardStep.allCases : steps, notice: notice)
            .environmentObject(model)
        let controller = NSHostingController(rootView: root)
        let window = NSWindow(contentViewController: controller)
        window.title = steps.count < WizardStep.allCases.count ? "Heartfulness Remote needs your OK" : "Set up Heartfulness Remote"
        window.styleMask = [.titled, .closable]
        window.setContentSize(NSSize(width: 640, height: 600))
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        wizardWindow = window
        present(window)
    }

    func closeWizard() {
        wizardWindow?.close()
    }

    var isWizardOpen: Bool { wizardWindow?.isVisible ?? false }

    private func present(_ window: NSWindow?) {
        guard let window else { return }
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        if window === wizardWindow {
            wizardWindow = nil
            AppModel.shared.wizardClosed()
        }
    }
}
