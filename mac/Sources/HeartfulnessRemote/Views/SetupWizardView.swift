import AppKit
import HRCore
import SwiftUI

/// First-run setup (all steps), or only the steps that need attention again — e.g. after an
/// update, when macOS forgets the Screen Recording / Accessibility permission of an ad-hoc
/// signed app.
struct SetupWizardView: View {
    @EnvironmentObject var model: AppModel

    let steps: [WizardStep]
    let notice: String?

    @State private var index: Int
    @State private var serverText = ""
    @State private var serverError: String?

    init(steps: [WizardStep], notice: String?) {
        let list = steps.isEmpty ? WizardStep.allCases : steps
        self.steps = list
        self.notice = notice
        var start = 0
        if list.count == WizardStep.allCases.count,
           let raw = UserDefaults.standard.object(forKey: "hr.wizardStep") as? Int,
           let saved = WizardStep(rawValue: raw),
           let position = list.firstIndex(of: saved) {
            start = position
        }
        _index = State(initialValue: start)
    }

    private var isFullSetup: Bool { steps.count == WizardStep.allCases.count }
    private var step: WizardStep { steps[min(max(index, 0), steps.count - 1)] }
    private var isLast: Bool { index >= steps.count - 1 }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let notice, index == 0 {
                        Label(notice, systemImage: "info.circle.fill")
                            .font(.callout)
                            .foregroundStyle(.blue)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                    stepContent
                }
                .padding(28)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            footer
        }
        .frame(width: 640, height: 600)
        .onAppear {
            if serverText.isEmpty { serverText = model.serverDisplayName }
            model.beginPermissionPolling()
            model.refreshFirewall()
        }
        .onDisappear {
            model.endPermissionPolling()
        }
    }

    // MARK: Header / footer

    private var header: some View {
        HStack(spacing: 14) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 44, height: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text(isFullSetup ? "Set up Heartfulness Remote" : "Heartfulness Remote needs your OK")
                    .font(.headline)
                Text("Step \(index + 1) of \(steps.count)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            ProgressView(value: Double(index + 1), total: Double(steps.count))
                .frame(width: 160)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var footer: some View {
        HStack {
            if index > 0 {
                Button("Back") { go(by: -1) }
            }
            Spacer()
            if isSkippable && !isDone(step) && !isLast {
                Button("Skip for Now") { go(by: 1) }
            }
            Button(isLast ? "Finish" : "Continue") { next() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    @ViewBuilder private var stepContent: some View {
        switch step {
        case .welcome:
            WelcomeStep()
        case .server:
            ServerStep(text: $serverText, error: serverError) { next() }
        case .screenRecording:
            ScreenRecordingStep()
        case .accessibility:
            AccessibilityStep()
        case .notifications:
            NotificationsStep()
        case .firewall:
            FirewallStep()
        case .launchAtLogin:
            LaunchAtLoginStep()
        case .pairPhone:
            PairPhoneStep()
        case .done:
            DoneStep()
        }
    }

    // MARK: Navigation

    private var isSkippable: Bool {
        switch step {
        case .welcome, .server, .done: return false
        default: return true
        }
    }

    private func isDone(_ step: WizardStep) -> Bool {
        switch step {
        case .screenRecording: return model.screenRecordingAllowed
        case .accessibility: return model.accessibilityAllowed
        case .notifications: return model.notificationsAllowed == true
        case .firewall: return model.firewall.fullyProtected
        case .launchAtLogin: return model.launchAtLoginEnabled
        case .pairPhone: return model.state.account == .inAccount
        default: return true
        }
    }

    private func next() {
        if step == .server {
            if let error = model.setServerAddress(serverText) {
                serverError = error
                return
            }
            serverError = nil
            serverText = model.serverDisplayName
        }
        if isLast {
            finish()
        } else {
            go(by: 1)
        }
    }

    private func go(by delta: Int) {
        index = min(max(index + delta, 0), steps.count - 1)
        if isFullSetup { model.saveWizardStep(steps[index]) }
    }

    private func finish() {
        if isFullSetup { model.completeSetup() }
        WindowManager.shared.closeWizard()
    }
}

// MARK: - Shared pieces

private struct StepTitle: View {
    let title: String
    let subtitle: String
    var symbol: String?

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            if let symbol {
                Image(systemName: symbol)
                    .font(.system(size: 34, weight: .semibold))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.blue)
                    .frame(width: 46)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(title)
                    .font(.system(size: 24, weight: .bold))
                Text(subtitle)
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// "Allowed ✓" / "Not allowed yet" in large type.
private struct DoneBadge: View {
    let done: Bool
    let doneText: String
    let pendingText: String

    var body: some View {
        Label(done ? doneText : pendingText,
              systemImage: done ? "checkmark.circle.fill" : "circle.dashed")
            .font(.title3.weight(.semibold))
            .foregroundStyle(done ? Color.green : Color.secondary)
    }
}

/// Numbered instructions.
private struct Steps: View {
    let items: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(items.enumerated()), id: \.offset) { item in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(item.offset + 1).")
                        .font(.body.weight(.semibold))
                        .monospacedDigit()
                    Text(item.element)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

private struct Hint: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "lightbulb")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - Steps

private struct WelcomeStep: View {
    /// Running from Downloads (or a translocated copy): "Open at login" and the firewall rule
    /// would point at a temporary location.
    private var outsideApplications: Bool {
        let path = Bundle.main.bundlePath
        return path.hasSuffix(".app")
            && !AppPlacement.isInApplicationsFolder(bundlePath: path, homeDirectory: NSHomeDirectory())
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            StepTitle(title: "Welcome to Heartfulness Remote",
                      subtitle: "Use this Mac from anywhere — from your phone, another computer, or any web browser. Setup takes about five minutes.")
            if outsideApplications {
                ProblemBox(title: "Please move the app to Applications first",
                           message: "Heartfulness Remote is not in your Applications folder, so it can't start by itself when you log in. Quit it (menu bar icon → Quit), drag it into Applications, and open it from there.",
                           color: .orange) {
                    Button("Show the App in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
                    }
                }
            }
            VStack(alignment: .leading, spacing: 14) {
                Label("Private: the picture, sound, mouse and keyboard are encrypted from end to end. Not even your own server can watch.",
                      systemImage: "lock.shield")
                Label("You decide: every new phone or computer must be approved by you, with a 6-digit code check.",
                      systemImage: "checkmark.shield")
                Label("Always visible: an orange banner appears on this Mac whenever someone is connected.",
                      systemImage: "person.crop.circle.badge.exclamationmark")
                Label("One-click stop: “Block all connections” in the menu bar, or press ⌃⌥⌘K anywhere.",
                      systemImage: "hand.raised.fill")
            }
            .font(.body)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct ServerStep: View {
    @EnvironmentObject var model: AppModel
    @Binding var text: String
    let error: String?
    let onSubmit: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepTitle(title: "Your server address",
                      subtitle: "Type the address of your own Heartfulness Remote server — the name you created for it, for example heartfulness-remote.duckdns.org.",
                      symbol: "server.rack")
            TextField("Server address", text: $text, prompt: Text("heartfulness-remote.duckdns.org"))
                .textFieldStyle(.roundedBorder)
                .font(.title3)
                .onSubmit { onSubmit() }
            if let error {
                Label(error, systemImage: "exclamationmark.circle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Hint(text: "Just the name is enough — “https://” is added for you.")
            if !model.settings.serverURL.isEmpty {
                GroupBox {
                    StatusHeader(summary: model.summary)
                        .padding(6)
                } label: {
                    Text("Connection")
                }
            }
        }
    }
}

private struct ScreenRecordingStep: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepTitle(title: "Allow screen sharing",
                      subtitle: "So your approved devices can see this screen and hear its sound, macOS needs you to allow “Screen Recording” for Heartfulness Remote. Nothing is shared until you approve a device and it connects.",
                      symbol: "rectangle.dashed.badge.record")
            DoneBadge(done: model.screenRecordingAllowed, doneText: "Screen Recording is allowed",
                      pendingText: "Not allowed yet")
            if !model.screenRecordingAllowed {
                Steps(items: [
                    "Click “Allow Screen Recording…”.",
                    "In System Settings, switch on Heartfulness Remote (type your Mac password if asked).",
                    "If macOS asks, click “Quit & Reopen”. Heartfulness Remote comes back by itself.",
                ])
                HStack(spacing: 10) {
                    Button("Allow Screen Recording…") { model.requestScreenRecording() }
                        .buttonStyle(.borderedProminent)
                    Button("Open System Settings") { Permissions.open(.screenRecording) }
                }
                Hint(text: "Is Heartfulness Remote already switched on in the list? After an update macOS needs a fresh OK: switch it off and on again — or select it, click “–”, and add it again with “+”.")
                HStack(spacing: 10) {
                    Text("Switched it on but this page doesn't notice?")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Button("Reopen Heartfulness Remote") { model.relaunch() }
                }
            }
        }
    }
}

private struct AccessibilityStep: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepTitle(title: "Allow mouse and keyboard control",
                      subtitle: "So you can click and type on this Mac from your other devices, macOS needs you to allow “Accessibility” for Heartfulness Remote.",
                      symbol: "cursorarrow.click")
            DoneBadge(done: model.accessibilityAllowed, doneText: "Mouse and keyboard control is allowed",
                      pendingText: "Not allowed yet")
            if !model.accessibilityAllowed {
                Steps(items: [
                    "Click “Allow Control…”, then “Open System Settings”.",
                    "Switch on Heartfulness Remote (type your Mac password if asked).",
                    "Come back here — this page updates by itself.",
                ])
                HStack(spacing: 10) {
                    Button("Allow Control…") { model.requestAccessibility() }
                        .buttonStyle(.borderedProminent)
                    Button("Open System Settings") { Permissions.open(.accessibility) }
                }
                Hint(text: "Already switched on? After an update macOS needs a fresh OK: switch Heartfulness Remote off and on again — or select it, click “–”, and add it again with “+”.")
            }
        }
    }
}

private struct NotificationsStep: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepTitle(title: "Get notified",
                      subtitle: "Heartfulness Remote tells you when someone connects, when a new device asks to be added, and shortly before an inactive session ends.",
                      symbol: "bell.badge")
            DoneBadge(done: model.notificationsAllowed == true, doneText: "Notifications are allowed",
                      pendingText: model.notificationsAllowed == false ? "Notifications are turned off" : "Not allowed yet")
            if model.notificationsAllowed != true {
                HStack(spacing: 10) {
                    Button("Allow Notifications") { model.requestNotifications() }
                        .buttonStyle(.borderedProminent)
                    Button("Open Notification Settings") { Permissions.open(.notifications) }
                }
                Hint(text: "Even without notifications, the orange banner always shows when someone is connected.")
            }
        }
    }
}

private struct FirewallStep: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepTitle(title: "Turn on the firewall",
                      subtitle: "The macOS firewall with “stealth mode” makes this Mac invisible to others on the network. Heartfulness Remote never needs incoming connections, so it keeps working.",
                      symbol: "lock.shield")
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    LabeledContent("Firewall") { StatusPill(ok: model.firewall.enabled) }
                    LabeledContent("Stealth mode") { StatusPill(ok: model.firewall.stealth) }
                }
                .padding(6)
            }
            if !model.firewall.fullyProtected {
                HStack(spacing: 10) {
                    Button("Turn On…") { model.enableFirewall() }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.firewallBusy)
                    if model.firewallBusy {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                Hint(text: "macOS asks for your Mac login password once. Heartfulness Remote doesn't see or keep it.")
            }
            if let message = model.firewallMessage {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct LaunchAtLoginStep: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepTitle(title: "Start automatically",
                      subtitle: "So you can always reach this Mac, Heartfulness Remote should open by itself when you log in. It lives quietly in the menu bar, top right.",
                      symbol: "power.circle")
            Toggle("Open Heartfulness Remote at login", isOn: $model.launchAtLogin)
                .toggleStyle(.switch)
                .font(.title3)
            if model.loginItemNeedsApproval {
                HStack(spacing: 10) {
                    Text("macOS needs your OK: switch on Heartfulness Remote in Login Items.")
                        .font(.callout)
                    Button("Open Login Items") { LoginItem.openSettings() }
                }
            }
            if let message = model.loginItemMessage {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// Unclaimed server → pair the first phone (creates the passkey). Claimed server, but this Mac
/// isn't in the account → "Add this Mac to your account" (QR code or Mac ID + code). In the
/// account → done.
private struct PairPhoneStep: View {
    @EnvironmentObject var model: AppModel

    private var connected: Bool { model.agentRunning && model.state.server == .online }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if model.state.account == .notInAccount && !model.settings.serverURL.isEmpty {
                StepTitle(title: AccountText.addTitle, subtitle: AccountText.addSubtitle,
                          symbol: "laptopcomputer.and.iphone")
            } else {
                StepTitle(title: "Pair your phone",
                          subtitle: "Your phone becomes the key to this Mac: it signs in with a passkey (Face ID, Touch ID or fingerprint — no password) and can approve your other devices.",
                          symbol: "iphone")
            }
            content
        }
    }

    @ViewBuilder private var content: some View {
        if model.settings.serverURL.isEmpty {
            Text("First type your server address (go back one step).")
                .foregroundStyle(.secondary)
        } else if !connected {
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    StatusHeader(summary: model.summary)
                    Text("The code appears here as soon as this Mac is connected to your server.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(6)
            }
        } else if model.state.account == .inAccount {
            VStack(alignment: .leading, spacing: 10) {
                DoneBadge(done: true, doneText: "This Mac is in your account", pendingText: "")
                if let line = model.macIDLine {
                    MacIDLabel(line: line)
                }
                Text(AccountText.inAccountDetail(serverName: model.serverDisplayName))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else if model.state.account == .notInAccount {
            if let image = model.joinQRCode(), let code = model.state.joinCode {
                JoinMacPanel(qrImage: image, macID: model.macIDText, joinCode: code)
            } else {
                preparing
            }
        } else if let image = model.setupQRCode() {
            HStack(alignment: .top, spacing: 22) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 210, height: 210)
                    .padding(12)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .accessibilityLabel(Text("Pairing code for your phone"))
                VStack(alignment: .leading, spacing: 12) {
                    Steps(items: [
                        "On your phone, open the Camera app.",
                        "Point it at this code and tap the link that appears.",
                        "Follow the steps on your phone to create your passkey.",
                        "This page updates by itself when it's done.",
                    ])
                    Label("Keep this code private. It works only once, and only with this Mac.",
                          systemImage: "lock.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } else {
            preparing
        }
    }

    private var preparing: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                Text("Preparing a code…")
            }
            Button("Make a New Code") { model.newSetupCode() }
        }
    }
}

private struct DoneStep: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            StepTitle(title: "You're all set",
                      subtitle: "Heartfulness Remote now lives in the menu bar at the top right of your screen.",
                      symbol: "checkmark.seal.fill")
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    summaryRow("Server", ok: model.state.server == .online)
                    summaryRow("In your account", ok: model.state.account == .inAccount)
                    summaryRow("Screen Recording", ok: model.screenRecordingAllowed)
                    summaryRow("Mouse and keyboard control", ok: model.accessibilityAllowed)
                    summaryRow("Firewall and stealth mode", ok: model.firewall.fullyProtected)
                    summaryRow("Opens at login", ok: model.launchAtLoginEnabled)
                }
                .padding(6)
            }
            VStack(alignment: .leading, spacing: 10) {
                Label("To connect, open \(model.settings.serverURL.isEmpty ? "your web address" : model.serverDisplayName) on any device and sign in with your passkey.",
                      systemImage: "globe")
                Label("Press ⌃⌥⌘K at any time to block all connections instantly.", systemImage: "hand.raised.fill")
                Label("Anything not done yet can be finished later in the Heartfulness Remote menu → Open Dashboard.",
                      systemImage: "macwindow")
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func summaryRow(_ title: String, ok: Bool) -> some View {
        LabeledContent(title) {
            StatusPill(ok: ok, okText: "Done", badText: "Not yet")
        }
    }
}
