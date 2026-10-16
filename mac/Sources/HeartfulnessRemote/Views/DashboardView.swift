import AppKit
import HRCore
import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationSplitView {
            List(selection: $model.dashboardSection) {
                ForEach(DashboardSection.allCases) { section in
                    Label(section.title, systemImage: section.symbol)
                        .badge(section == .approvals ? model.state.pending.count : 0)
                        .tag(Optional(section))
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
        } detail: {
            DashboardDetail(section: model.dashboardSection ?? .status)
        }
        .frame(minWidth: 780, minHeight: 520)
        .onAppear {
            model.beginPermissionPolling()
            model.refreshFirewall()
        }
        .onDisappear {
            model.endPermissionPolling()
        }
        .alert("Heartfulness Remote", isPresented: $model.showingNotice) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.notice ?? "")
        }
    }
}

private struct DashboardDetail: View {
    let section: DashboardSection

    var body: some View {
        switch section {
        case .status: StatusPage()
        case .devices: DevicesPage()
        case .approvals: ApprovalsPage()
        case .log: AccessLogPage()
        case .settings: SettingsPage()
        }
    }
}

/// A scrollable page with a title.
private struct Page<Content: View>: View {
    let title: String
    @ViewBuilder var content: () -> Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(title)
                    .font(.largeTitle.weight(.bold))
                content()
            }
            .padding(28)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Status

private struct StatusPage: View {
    @EnvironmentObject var model: AppModel
    @State private var confirmNewIdentity = false
    @State private var confirmStartFresh = false

    var body: some View {
        Page(title: "Status") {
            statusCard
            problems
            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    LabeledContent("Server") {
                        Text(model.settings.serverURL.isEmpty ? "Not set up yet" : model.serverDisplayName)
                            .textSelection(.enabled)
                    }
                    LabeledContent("This Mac's key") {
                        Text(model.hostFingerprint.isEmpty ? "—" : model.hostFingerprint)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    LabeledContent("Key protection") {
                        Text(model.keyProtection?.rawValue ?? "—")
                    }
                    LabeledContent("Kill switch shortcut") {
                        Text(model.hotKeyAvailable ? "⌃⌥⌘K" : "Not available (another app uses ⌃⌥⌘K)")
                    }
                    Text("Compare “This Mac's key” with the one your phone shows when you add a device: if they match, you are talking to this Mac.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(6)
            } label: {
                Label("This Mac", systemImage: "desktopcomputer")
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    LabeledContent("Firewall") { StatusPill(ok: model.firewall.enabled) }
                    LabeledContent("Stealth mode") { StatusPill(ok: model.firewall.stealth) }
                    if !model.firewall.fullyProtected {
                        HStack {
                            Button("Turn On…") { model.enableFirewall() }
                                .disabled(model.firewallBusy)
                            Text("macOS asks for your Mac password once.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let message = model.firewallMessage {
                        Text(message)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(6)
            } label: {
                Label("Network protection", systemImage: "lock.shield")
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    permissionRow("Screen Recording (screen and sound)", ok: model.screenRecordingAllowed, step: .screenRecording)
                    permissionRow("Accessibility (mouse and keyboard)", ok: model.accessibilityAllowed, step: .accessibility)
                    permissionRow("Notifications", ok: model.notificationsAllowed, step: .notifications)
                    LabeledContent("Open at login") {
                        Toggle("Open at login", isOn: $model.launchAtLogin)
                            .labelsHidden()
                            .toggleStyle(.switch)
                    }
                    if model.loginItemNeedsApproval {
                        HStack {
                            Text("Switch on Heartfulness Remote in System Settings → General → Login Items.")
                                .font(.caption)
                            Button("Open Login Items") { LoginItem.openSettings() }
                        }
                    }
                    if let message = model.loginItemMessage {
                        Text(message).font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(6)
            } label: {
                Label("Permissions", systemImage: "checkmark.shield")
            }
        }
        .alert("Create a new identity for this Mac?", isPresented: $confirmNewIdentity) {
            Button("Create New Identity", role: .destructive) { model.createNewIdentity() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Every device will have to be approved again, and your phone must be paired again.")
        }
        .alert("Start fresh?", isPresented: $confirmStartFresh) {
            Button("Start Fresh", role: .destructive) { model.resetTrustStore() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The current device list and access log are kept as evidence next to the new ones. You will pair your phone and devices again.")
        }
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            StatusHeader(summary: model.summary, size: .large)
            if let session = model.state.session {
                SessionControls(session: session, onDisconnect: { model.disconnectNow() }, large: true)
            }
            if model.agentRunning || model.connectionsBlocked {
                Divider()
                BlockConnectionsToggle()
            }
            if model.state.server == .online && !model.state.claimed && model.agentRunning {
                Button {
                    model.openSetup(steps: [.pairPhone])
                } label: {
                    Label("Pair your phone…", systemImage: "qrcode")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(model.summary.kind.color.opacity(0.45), lineWidth: 2)
        )
    }

    @ViewBuilder private var problems: some View {
        if let error = model.identityError {
            ProblemBox(title: error.title, message: error.message) {
                Button("Try Again") { model.retryIdentity() }
                if error.allowsReset {
                    Button("Create New Identity…", role: .destructive) { confirmNewIdentity = true }
                }
            }
        }
        if model.trustStoreProblem {
            ProblemBox(title: "Connections refused for safety",
                       message: ServerErrorText.message(for: model.state.serverError ?? "")) {
                Button("Start Fresh…", role: .destructive) { confirmStartFresh = true }
            }
        }
        if let problem = model.captureProblem {
            ProblemBox(title: "The screen can't be shared", message: problem, color: .orange) {
                Button("Fix…") { model.openSetup(steps: [.screenRecording]) }
            }
        }
        if model.inputBlockedByPermission && !model.accessibilityAllowed {
            ProblemBox(title: "Mouse and keyboard are blocked",
                       message: "The connected device can see your screen but can't control it until you allow Accessibility.",
                       color: .orange) {
                Button("Fix…") { model.openSetup(steps: [.accessibility]) }
            }
        }
    }

    private func permissionRow(_ title: String, ok: Bool?, step: WizardStep) -> some View {
        LabeledContent(title) {
            HStack(spacing: 10) {
                StatusPill(ok: ok, okText: "Allowed", badText: "Not allowed", unknownText: "Not decided")
                if ok != true {
                    Button("Fix…") { model.openSetup(steps: [step]) }
                }
            }
        }
    }
}

// MARK: - Devices

private struct DevicesPage: View {
    @EnvironmentObject var model: AppModel
    @State private var deviceToRemove: TrustedDevice?
    @State private var confirmRemove = false

    var body: some View {
        Page(title: "Devices") {
            Text("These devices may connect to this Mac (after signing in with your passkey). Remove any device you no longer use or don't recognise.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if model.state.devices.isEmpty {
                ContentUnavailableView("No devices yet",
                                       systemImage: "laptopcomputer.and.iphone",
                                       description: Text("Pair your phone in the setup window. To add a computer, open your web address on it, sign in, and approve it here."))
                    .frame(maxWidth: .infinity, minHeight: 240)
            } else {
                VStack(spacing: 10) {
                    ForEach(model.state.devices) { device in
                        DeviceRow(device: device) {
                            deviceToRemove = device
                            confirmRemove = true
                        }
                    }
                }
            }
            GroupBox {
                Text("To add a device: open \(model.settings.serverURL.isEmpty ? "your web address" : model.serverDisplayName) on it (or the Heartfulness Remote app), sign in with your passkey, then approve it on the Approvals page or on your phone — after checking that the 6-digit codes match.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(6)
            } label: {
                Label("Add a device", systemImage: "plus.circle")
            }
        }
        .alert("Remove this device?", isPresented: $confirmRemove, presenting: deviceToRemove) { device in
            Button("Remove", role: .destructive) { model.remove(device) }
            Button("Cancel", role: .cancel) {}
        } message: { device in
            Text("“\(device.displayName)” will no longer be able to connect to this Mac. If it is connected now, it is disconnected immediately.")
        }
    }
}

private struct DeviceRow: View {
    let device: TrustedDevice
    let onRemove: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: DeviceStyle.symbol(kind: device.kind, name: device.name))
                .font(.system(size: 26))
                .foregroundStyle(.blue)
                .frame(width: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text(device.displayName)
                    .font(.headline)
                Text(details)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if !device.fingerprint.isEmpty {
                    Text("Key: \(device.fingerprint)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            Spacer()
            Button("Remove…", role: .destructive, action: onRemove)
        }
        .padding(12)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    private var details: String {
        var parts = [DeviceKindText.label(device.kind)]
        if let added = device.addedAt?.date {
            parts.append("added " + added.formatted(date: .abbreviated, time: .omitted))
        }
        if let used = device.lastUsed?.date {
            parts.append("last used " + used.formatted(.relative(presentation: .named)))
        } else {
            parts.append("never used")
        }
        return parts.joined(separator: " · ")
    }
}

// MARK: - Approvals

private struct ApprovalsPage: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Page(title: "Approvals") {
            if model.state.pending.isEmpty {
                ContentUnavailableView("No devices are waiting",
                                       systemImage: "checkmark.shield",
                                       description: Text("When a new phone, computer or browser asks to control this Mac, it appears here with a 6-digit code."))
                    .frame(maxWidth: .infinity, minHeight: 280)
            } else {
                Text("A new device wants to control this Mac. Check that the code below is exactly the same as the code on that device.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(model.state.pending) { request in
                    ApprovalCard(request: request)
                }
            }
        }
    }
}

// MARK: - Access log

private struct AccessLogPage: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                Text("Access Log")
                    .font(.largeTitle.weight(.bold))
                Spacer()
                if model.logLoading {
                    ProgressView()
                        .controlSize(.small)
                }
                Button {
                    model.refreshLog()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(!model.agentRunning)
            }
            if let log = model.logResult {
                verification(log)
                let entries = log.displayEntries
                if entries.isEmpty {
                    ContentUnavailableView("Nothing recorded yet", systemImage: "list.bullet.rectangle",
                                           description: Text("Every connection, new device and kill-switch use is recorded here."))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    AccessLogTable(entries: entries)
                }
            } else if model.agentRunning {
                ProgressView("Reading the log…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView("Log not available right now", systemImage: "list.bullet.rectangle",
                                       description: Text("The log can be read once Heartfulness Remote is running and set up."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(28)
        .onAppear { model.refreshLog() }
    }

    @ViewBuilder private func verification(_ log: LogResult) -> some View {
        if log.verified {
            Label("Log verified ✓ — nothing was changed or removed.", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
                .font(.callout.weight(.medium))
        } else {
            ProblemBox(title: "Warning: the access log may have been tampered with",
                       message: "Heartfulness Remote found entries that were changed, removed or reordered outside the app"
                        + (log.error.map { " (\($0))" } ?? "")
                        + ". If you didn't expect this, someone with access to this Mac may have tried to hide what happened.") {
                EmptyView()
            }
        }
    }
}

private struct AccessLogTable: View {
    let entries: [AccessLogEntry]

    var body: some View {
        Table(entries) {
            TableColumn("When") { (entry: AccessLogEntry) in
                Text(entry.time.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 130, ideal: 160, max: 200)
            TableColumn("What") { (entry: AccessLogEntry) in
                Text(entry.title)
                    .foregroundStyle(entry.isWarning ? Color.red : Color.primary)
            }
            .width(min: 140, ideal: 200, max: 320)
            TableColumn("Device") { (entry: AccessLogEntry) in
                Text(entry.device ?? "—")
            }
            .width(min: 90, ideal: 140, max: 240)
            TableColumn("Details") { (entry: AccessLogEntry) in
                Text(entry.summary)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Settings

private struct SettingsPage: View {
    @EnvironmentObject var model: AppModel
    @State private var serverText = ""
    @State private var serverError: String?
    @State private var serverSaved = false
    @State private var confirmStartFresh = false
    @State private var showClaimedInfo = false

    var body: some View {
        Form {
            Section {
                HStack {
                    TextField("Server address", text: $serverText, prompt: Text("heartfulness-remote.duckdns.org"))
                        .onSubmit { saveServer() }
                    Button("Save") { saveServer() }
                        .disabled(serverText.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                if let serverError {
                    Text(serverError)
                        .font(.callout)
                        .foregroundStyle(.red)
                } else if serverSaved {
                    Text("Saved. Heartfulness Remote reconnects to this address.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                LabeledContent("Status", value: model.summary.title)
            } header: {
                Text("Server")
            } footer: {
                Text("Just the name is enough, for example heartfulness-remote.duckdns.org — https:// is added for you.")
            }

            Section {
                Toggle("Allow web browsers to connect", isOn: $model.settings.allowBrowserClients)
                Toggle("Always use the relay server", isOn: $model.settings.relayOnly)
                Picker("Disconnect after no activity for", selection: $model.settings.idleTimeoutMin) {
                    ForEach(idleChoices, id: \.self) { minutes in
                        Text(SettingsText.idle(minutes: minutes)).tag(minutes)
                    }
                }
            } header: {
                Text("Connections")
            } footer: {
                Text("Turning off web browsers leaves only the Heartfulness Remote apps, which is the most secure. The relay hides this Mac's network address but can be a little slower.")
            }

            Section {
                Picker("Video format", selection: $model.settings.codec) {
                    ForEach(CodecPreference.allCases) { codec in
                        Text(codec.title).tag(codec)
                    }
                }
                Picker("Maximum quality", selection: $model.settings.maxKbps) {
                    ForEach(bitrateChoices, id: \.self) { kbps in
                        Text(SettingsText.bitrate(kbps: kbps)).tag(kbps)
                    }
                }
                if !model.hevcAvailable {
                    Text("This Mac can't encode HEVC in hardware, so H.264 is used.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Picture")
            } footer: {
                Text("Higher quality needs a faster internet connection. Heartfulness Remote lowers it automatically when the connection is slow.")
            }

            Section {
                Toggle("Open at login", isOn: $model.launchAtLogin)
                if model.loginItemNeedsApproval {
                    HStack {
                        Text("Switch on Heartfulness Remote in System Settings → General → Login Items.")
                            .font(.caption)
                        Button("Open Login Items") { LoginItem.openSettings() }
                    }
                }
                LabeledContent("Kill switch shortcut", value: model.hotKeyAvailable ? "⌃⌥⌘K" : "Not available")
                Button("Show Setup Again…") { model.openSetup() }
                Button("New Phone Setup Code…") { newSetupCode() }
            } header: {
                Text("This Mac")
            }

            if model.trustStoreProblem {
                Section {
                    Text(ServerErrorText.message(for: model.state.serverError ?? ""))
                        .font(.callout)
                    Button("Start Fresh…", role: .destructive) { confirmStartFresh = true }
                } header: {
                    Text("Start fresh")
                }
            }

            Section {
                LabeledContent("Version", value: HostInfo.appVersion)
                LabeledContent("Key protection", value: model.keyProtection?.rawValue ?? "—")
            } header: {
                Text("About")
            }
        }
        .formStyle(.grouped)
        .onAppear {
            if serverText.isEmpty { serverText = model.serverDisplayName }
        }
        .alert("Start fresh?", isPresented: $confirmStartFresh) {
            Button("Start Fresh", role: .destructive) { model.resetTrustStore() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The current device list and access log are kept as evidence next to the new ones. You will pair your phone and devices again.")
        }
        .alert("Your phone is already paired", isPresented: $showClaimedInfo) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Your server already has an owner, so no setup code is needed. To add another phone or computer, open your web address on it, sign in with your passkey and approve it here or on your phone.")
        }
    }

    private var idleChoices: [Int] {
        var choices = HostSettings.idleTimeoutChoices
        if !choices.contains(model.settings.idleTimeoutMin) { choices.append(model.settings.idleTimeoutMin) }
        return choices.sorted()
    }

    private var bitrateChoices: [Int] {
        var choices = HostSettings.bitrateChoicesKbps
        if !choices.contains(model.settings.maxKbps) { choices.append(model.settings.maxKbps) }
        return choices.sorted()
    }

    private func saveServer() {
        if let error = model.setServerAddress(serverText) {
            serverError = error
            serverSaved = false
        } else {
            serverError = nil
            serverSaved = true
            serverText = model.serverDisplayName
        }
    }

    private func newSetupCode() {
        if model.state.claimed {
            showClaimedInfo = true
        } else {
            model.newSetupCode()
            model.openSetup(steps: [.pairPhone])
        }
    }
}
