import AppKit
import CoreGraphics
import Foundation
import HRCore

/// The app's coordinator. Owns the host identity, the hr-agent helper and every Mac-side
/// component, routes IPC frames (PROTOCOL.md §9) and publishes state for the SwiftUI views.
///
/// Threading: everything here is main-actor isolated. IPC frames arrive on the helper's
/// stdout reader thread; latency-sensitive ones (INPUT, ENCODER, AUDIO_CTL, SIGN_REQUEST)
/// are handled right there by thread-safe components, the rest hop to the main actor.
@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    private enum Keys {
        static let settings = "hr.settings"
        static let wizardStep = "hr.wizardStep"
        static let lastVersion = "hr.lastLaunchedVersion"
    }

    /// Entries requested from the agent for the Access Log page.
    static let logReadLimit = 500

    // MARK: Published state

    /// Latest STATE from the agent (marked offline while the helper is not running).
    @Published private(set) var state = AgentState()
    @Published private(set) var agentRunning = false
    /// The helper is missing or keeps crashing.
    @Published private(set) var agentProblem: String?
    /// The host identity could not be loaded from the keychain.
    @Published private(set) var identityError: HostKeyError?
    @Published private(set) var hostFingerprint = ""
    /// This Mac's ID (nine digits, from the host key; PROTOCOL.md §10.1). "" without an identity.
    @Published private(set) var hostMacID = ""
    @Published private(set) var keyProtection: KeyProtection?
    @Published private(set) var logResult: LogResult?
    @Published private(set) var logLoading = false
    @Published private(set) var firewall = FirewallState()
    @Published private(set) var firewallBusy = false
    @Published private(set) var firewallMessage: String?
    @Published private(set) var screenRecordingAllowed = false
    @Published private(set) var accessibilityAllowed = false
    /// nil = not decided yet
    @Published private(set) var notificationsAllowed: Bool?
    @Published private(set) var captureProblem: String?
    @Published private(set) var inputBlockedByPermission = false
    @Published private(set) var launchAtLoginEnabled = false
    @Published private(set) var loginItemNeedsApproval = false
    @Published private(set) var loginItemMessage: String?
    @Published private(set) var hotKeyAvailable = false
    @Published private(set) var hevcAvailable = false
    @Published private(set) var audioAvailable = false
    /// The owner pressed the kill switch while the helper was not running; sent on next start.
    @Published private(set) var pendingKill = false
    /// The owner allowed connections again while the helper was not running.
    @Published private(set) var pendingResume = false
    /// Short feedback for the owner (shown in the dashboard), e.g. after a failed command.
    @Published var notice: String?

    /// Alert binding for `notice` (`$model.showingNotice`).
    var showingNotice: Bool {
        get { notice != nil }
        set { if !newValue { notice = nil } }
    }

    /// Everything the owner can change; persisted and forwarded to the agent on change.
    @Published var settings: HostSettings {
        didSet { settingsDidChange(from: oldValue) }
    }

    @Published var dashboardSection: DashboardSection? = .status

    // MARK: Components

    let agent: AgentProcess
    let capture: CaptureEngine
    let input: InputInjector
    let banner = SessionBanner()
    let notifier = Notifier()
    let hotKey = GlobalHotKey()
    private var clipboard: ClipboardSync?
    private var signer: HostSigner?

    // MARK: Lifecycle state

    private var launched = false
    private var quitting = false
    private var helperMissing = false
    private var agentStopping = false
    private var agentStartedAt = Date.distantPast
    private var backoff = RestartBackoff()
    private var quickExits = 0
    private var restartTask: Task<Void, Never>?
    private var pollTask: Task<Void, Never>?
    private var pollers = 0
    private var screenObserver: NSObjectProtocol?
    private var activeDisplayID: CGDirectDisplayID = 0
    private var qrCache: (text: String, image: NSImage)?
    /// Keeps App Nap and idle sleep away while someone is connected.
    private var sessionActivity: NSObjectProtocol?

    private init() {
        settings = AppModel.loadSettings()
        let agentProcess = AgentProcess()
        agent = agentProcess
        capture = CaptureEngine(agent: agentProcess)
        input = InputInjector()
        clipboard = ClipboardSync(send: { [weak self] text in
            self?.sendClipboard(text)
        })
    }

    // MARK: Derived state

    /// The big status shown everywhere (menu bar icon, panel, dashboard).
    var summary: HostStatusSummary {
        HostStatusSummary.make(state: state, agentRunning: agentRunning,
                               serverAddress: settings.serverURL, problem: localProblem)
    }

    /// A local problem that stops everything (shown instead of the normal status).
    var localProblem: String? {
        if let identityError { return identityError.message }
        return agentProblem
    }

    var serverDisplayName: String { ServerAddress.displayName(settings.serverURL) }

    /// "482 913 557" — computed from the host key, so it shows even before the helper reports it.
    var macIDText: String {
        MacIDFormatter.format(hostMacID.isEmpty ? state.macId : hostMacID)
    }

    /// "Mac ID 482 913 557", or nil while no identity is loaded.
    var macIDLine: String? {
        AccountText.macIDLine(hostMacID.isEmpty ? state.macId : hostMacID)
    }

    /// The server is online, has an owner, but this Mac isn't in the owner's account yet.
    var needsJoin: Bool {
        agentRunning && state.server == .online && state.account == .notInAccount
    }

    /// The kill switch. Settable so a SwiftUI Toggle can bind to it (`$model.connectionsBlocked`).
    var connectionsBlocked: Bool {
        get { pendingKill || (state.killed && !pendingResume) }
        set { setConnectionsBlocked(newValue) }
    }

    /// "Open at login". Settable so a SwiftUI Toggle can bind to it.
    var launchAtLogin: Bool {
        get { launchAtLoginEnabled }
        set { setLaunchAtLogin(newValue) }
    }

    /// The agent's trust store is unusable (tampered / foreign identity): "Start fresh" is offered.
    var trustStoreProblem: Bool {
        state.server == .error && ServerErrorText.isTrustStoreProblem(state.serverError ?? "")
    }

    var isFirstSetupDone: Bool { settings.setupCompleted }

    // MARK: Launch

    /// Called once from applicationDidFinishLaunching (after the single-instance and
    /// "Move to Applications" checks).
    func launch() {
        guard !launched else { return }
        launched = true

        let defaults = UserDefaults.standard
        let thisVersion = HostInfo.appVersion
        let lastVersion = defaults.string(forKey: Keys.lastVersion)
        defaults.set(thisVersion, forKey: Keys.lastVersion)
        let updated = lastVersion != nil && lastVersion != thisVersion

        notifier.setUp()
        notifier.onOpen = { isPairing in
            onMain {
                WindowManager.shared.showDashboard(section: isPairing ? .approvals : nil)
            }
        }
        wireComponents()

        hevcAvailable = VideoEncoder.isHEVCEncodeAvailable()
        audioAvailable = AudioEncoder.isAvailable()
        capture.setCapabilities(hevc: hevcAvailable, audio: audioAvailable)

        hotKeyAvailable = hotKey.registerKillShortcut { [weak self] in
            self?.killFromHotKey()
        }
        observeScreens()
        loadIdentity()
        refreshPermissions()
        refreshLoginItem()
        refreshFirewall()
        startAgentIfPossible()
        showWizardIfNeeded(afterUpdate: updated)
    }

    private func wireComponents() {
        let input = self.input
        capture.onActiveDisplayChanged = { id in
            input.setDefaultDisplay(id)
            onMain { AppModel.shared.activeDisplayID = id }
        }
        capture.onProblem = { message in
            onMain { AppModel.shared.captureProblemChanged(message) }
        }
        input.onBlockedByPermission = {
            onMain { AppModel.shared.inputWasBlocked() }
        }
        agent.onExit = { status in
            onMain { AppModel.shared.agentExited(status: status) }
        }
    }

    private func showWizardIfNeeded(afterUpdate: Bool) {
        if !settings.setupCompleted {
            WindowManager.shared.showWizard()
            return
        }
        var missing: [WizardStep] = []
        if !screenRecordingAllowed { missing.append(.screenRecording) }
        if !accessibilityAllowed { missing.append(.accessibility) }
        guard !missing.isEmpty else { return }
        let notice = afterUpdate
            ? "Heartfulness Remote was updated, so macOS asks you to allow it again. This is normal and takes a moment."
            : "macOS turned off a permission Heartfulness Remote needs. Please allow it again."
        WindowManager.shared.showWizard(steps: missing, notice: notice)
    }

    // MARK: Identity

    func loadIdentity() {
        switch HostKeyStore.loadOrCreate() {
        case .success(let loaded):
            signer = loaded
            identityError = nil
            hostFingerprint = loaded.fingerprint
            hostMacID = loaded.macID
            keyProtection = loaded.protection
        case .failure(let error):
            signer = nil
            identityError = error
            hostFingerprint = ""
            hostMacID = ""
            keyProtection = nil
            Log.keys.error("Host identity unavailable: \(error.title, privacy: .public)")
        }
    }

    /// "Try again" after a keychain prompt was denied or cancelled.
    func retryIdentity() {
        loadIdentity()
        startAgentIfPossible()
    }

    /// Owner-confirmed: replace an unreadable identity with a new one. Devices must be
    /// paired again (the agent will then report its old trust store as foreign → "Start fresh").
    func createNewIdentity() {
        HostKeyStore.deleteIdentity()
        loadIdentity()
        restartAgent()
    }

    // MARK: Helper process

    func startAgentIfPossible() {
        restartTask?.cancel()
        restartTask = nil
        guard launched, !quitting, !agentStopping, !agent.isRunning else { return }
        guard let signer, !settings.serverURL.isEmpty else { return }

        let config = AgentConfig(
            serverURL: settings.serverURL,
            hostPub: signer.publicKeyB64,
            hostName: HostInfo.computerName(),
            dataDir: HostInfo.dataDirectory().path,
            storageKey: Base64URL.encode(signer.storageKey),
            settings: settings.agentSettings,
            hevcAvailable: hevcAvailable,
            audioAvailable: audioAvailable
        )
        agent.onFrame = AppModel.makeFrameHandler(agent: agent, signer: signer, input: input, capture: capture)
        do {
            try agent.start(config: config)
        } catch AgentProcess.LaunchError.helperMissing {
            helperMissing = true
            agentProblem = "Part of Heartfulness Remote is missing (its connection helper). Please download the app again and replace this copy."
            return
        } catch {
            Log.agent.error("Could not start hr-agent: \(error.localizedDescription, privacy: .public)")
            agentProblem = "The connection helper could not start (\(error.localizedDescription))."
            scheduleAgentStart(after: backoff.delay(afterUptime: 0))
            return
        }
        helperMissing = false
        agentRunning = true
        agentStartedAt = Date()
        sendDisplays()
        if pendingKill {
            agent.send(command: .kill)
        } else if pendingResume {
            agent.send(command: .resume)
        }
        pendingKill = false
        pendingResume = false
    }

    /// Stops the helper, waits for it to exit, then starts it again (new server address,
    /// new identity). Never runs two helpers at once.
    func restartAgent() {
        restartTask?.cancel()
        restartTask = nil
        guard !agentStopping else { return }   // the stop in progress restarts it anyway
        agentStopping = true
        agentRunning = false
        endSessionLocally()
        markOffline()
        agent.stop {
            onMain { AppModel.shared.agentDidStopForRestart() }
        }
    }

    private func agentDidStopForRestart() {
        agentStopping = false
        backoff.reset()
        quickExits = 0
        startAgentIfPossible()
    }

    private func agentExited(status: Int32) {
        agentRunning = false
        endSessionLocally()
        markOffline()
        guard !quitting else { return }
        let uptime = Date().timeIntervalSince(agentStartedAt)
        quickExits = uptime < 15 ? quickExits + 1 : 0
        if quickExits >= 3 {
            agentProblem = "The connection helper keeps stopping (code \(status)). Heartfulness Remote keeps trying. If this doesn't go away, restart your Mac or download the app again."
        }
        scheduleAgentStart(after: backoff.delay(afterUptime: uptime))
    }

    private func scheduleAgentStart(after seconds: Double) {
        restartTask?.cancel()
        let nanos = UInt64(max(0.2, seconds) * 1_000_000_000)
        restartTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: nanos)
            guard !Task.isCancelled else { return }
            self?.startAgentIfPossible()
        }
    }

    /// Keeps the last known devices / kill state, but nothing live.
    private func markOffline() {
        var s = state
        s.server = .offline
        s.serverError = nil
        s.session = nil
        s.pending = []
        s.setupURL = nil
        s.joinURL = nil
        s.joinCode = nil
        state = s
        qrCache = nil
    }

    /// Routes frames from the helper. Runs on the stdout reader thread.
    nonisolated private static func makeFrameHandler(agent: AgentProcess, signer: HostSigner,
                                                     input: InputInjector, capture: CaptureEngine) -> @Sendable (IPCFrame) -> Void {
        return { frame in
            guard let type = frame.knownType else { return }
            let decoder = JSONDecoder()
            switch type {
            case .input:
                if let message = try? decoder.decode(InputMessage.self, from: frame.payload) {
                    input.handle(message)
                }
            case .encoder:
                if let command = try? decoder.decode(EncoderCommand.self, from: frame.payload) {
                    capture.handle(command)
                }
            case .audioControl:
                if let control = try? decoder.decode(AudioControl.self, from: frame.payload) {
                    capture.setAudioEnabled(control.isStart)
                }
            case .signRequest:
                if let request = try? decoder.decode(SignRequest.self, from: frame.payload) {
                    agent.sendJSON(.signResult, signer.respond(to: request))
                }
            case .state:
                if let state = try? decoder.decode(AgentState.self, from: frame.payload) {
                    onMain { AppModel.shared.apply(state: state) }
                }
            case .event:
                if let event = try? decoder.decode(AgentEvent.self, from: frame.payload) {
                    onMain { AppModel.shared.handle(event: event) }
                }
            case .clipboardSet:
                if let message = try? decoder.decode(ClipboardSet.self, from: frame.payload) {
                    onMain { AppModel.shared.applyRemoteClipboard(message.text) }
                }
            case .log:
                if let log = try? decoder.decode(LogResult.self, from: frame.payload) {
                    onMain { AppModel.shared.apply(log: log) }
                }
            case .config, .signResult, .video, .audio, .command:
                break   // Swift → agent types; the agent never sends them
            }
        }
    }

    // MARK: Frames from the helper (main actor)

    private func apply(state new: AgentState) {
        guard agentRunning else { return }   // late frames from a helper that is stopping
        let old = state
        state = new
        if new.server == .online {
            quickExits = 0
            if !helperMissing { agentProblem = nil }
        }
        if !new.killed { pendingResume = false }
        if new.killed != old.killed {
            input.setEnabled(!new.killed)
            if new.killed { endSessionLocally() }
        }
        if let session = new.session {
            showBanner(for: session.device.displayName)
            clipboard?.start()
        } else if old.session != nil || banner.isVisible {
            banner.hide()
            clipboard?.stop()
            if let activity = sessionActivity {
                ProcessInfo.processInfo.endActivity(activity)
                sessionActivity = nil
            }
        }
        if new.setupURL != old.setupURL || new.joinURL != old.joinURL { qrCache = nil }
    }

    private func handle(event: AgentEvent) {
        switch event.event {
        case "session-start":
            showBanner(for: event.deviceName)
            clipboard?.start()
        case "session-end":
            endSessionLocally()
        case "killed":
            endSessionLocally()
            input.setEnabled(false)
        case "resumed":
            input.setEnabled(true)
        case "log-tampered":
            logResult = nil
        default:
            break
        }
        if let note = EventNotification.make(for: event) {
            notifier.post(title: note.title, body: note.body, identifier: note.identifier,
                          category: note.isPairing ? Notifier.pairCategory : nil)
        }
    }

    private func apply(log: LogResult) {
        logResult = log
        logLoading = false
    }

    private func applyRemoteClipboard(_ text: String) {
        guard state.session != nil || banner.isVisible, !connectionsBlocked else { return }
        clipboard?.setFromRemote(text)
    }

    private func sendClipboard(_ text: String) {
        guard state.session != nil, !connectionsBlocked, agentRunning else { return }
        agent.send(command: .clipboard(text: text))
    }

    private func showBanner(for deviceName: String) {
        // Both actions run on the next main-loop turn: blocking hides (and releases) the banner
        // panel whose button is being clicked.
        banner.show(deviceName: deviceName,
                    onDisconnect: { onMain { AppModel.shared.disconnectNow() } },
                    onBlock: { onMain { AppModel.shared.setConnectionsBlocked(true) } })
        if sessionActivity == nil {
            sessionActivity = ProcessInfo.processInfo.beginActivity(
                options: [.userInitiated, .idleDisplaySleepDisabled, .latencyCritical],
                reason: "A remote session is active")
        }
    }

    /// Stops everything session-related on this side immediately (defence in depth: the agent
    /// also sends ENCODER stop / AUDIO_CTL stop).
    private func endSessionLocally() {
        capture.stopAll()
        input.reset()
        clipboard?.stop()
        banner.hide()
        if let activity = sessionActivity {
            ProcessInfo.processInfo.endActivity(activity)
            sessionActivity = nil
        }
    }

    private func captureProblemChanged(_ message: String?) {
        captureProblem = message
        if let message, state.session != nil {
            notifier.post(title: "The screen can't be shared", body: message, identifier: "hr.capture")
        }
    }

    private func inputWasBlocked() {
        inputBlockedByPermission = true
        notifier.post(title: "Allow Heartfulness Remote to control this Mac",
                      body: "The connected device can see your screen, but its mouse and keyboard don't work yet. Open Heartfulness Remote → Status to allow Accessibility.",
                      identifier: "hr.permission.accessibility")
    }

    // MARK: Owner actions

    func disconnectNow() {
        agent.send(command: .disconnect)
        capture.stopAll()
        input.reset()
    }

    func setConnectionsBlocked(_ blocked: Bool) {
        if blocked {
            endSessionLocally()
            input.setEnabled(false)
            pendingResume = false
            if !(agentRunning && agent.send(command: .kill)) {
                pendingKill = true
            }
        } else {
            pendingKill = false
            input.setEnabled(true)
            if !(agentRunning && agent.send(command: .resume)) {
                pendingResume = state.killed
            }
        }
        objectWillChange.send()
    }

    /// ⌃⌥⌘K anywhere: block (never toggles, so pressing it twice is always safe).
    private func killFromHotKey() {
        let wasBlocked = connectionsBlocked
        setConnectionsBlocked(true)
        if !agentRunning || wasBlocked {
            notifier.post(title: "Connections blocked",
                          body: "Nobody can connect to this Mac until you allow connections again from the Heartfulness Remote menu.",
                          identifier: "hr.kill")
        }
    }

    func approve(_ request: PendingApproval) {
        if !agent.send(command: .approve(requestId: request.requestId)) { helperUnavailableNotice() }
    }

    func deny(_ request: PendingApproval) {
        if !agent.send(command: .deny(requestId: request.requestId)) { helperUnavailableNotice() }
    }

    func remove(_ device: TrustedDevice) {
        if !agent.send(command: .revoke(devicePub: device.pub)) { helperUnavailableNotice() }
    }

    func refreshLog() {
        guard agentRunning, agent.send(command: .logRead(limit: AppModel.logReadLimit)) else {
            logLoading = false
            return
        }
        logLoading = true
    }

    func newSetupCode() {
        qrCache = nil
        if !agent.send(command: .newSetupCode) { helperUnavailableNotice() }
    }

    /// Only does something while the trust store is unusable (the agent refuses otherwise).
    func resetTrustStore() {
        if !agent.send(command: .resetTrustStore) { helperUnavailableNotice() }
    }

    private func helperUnavailableNotice() {
        notice = "Heartfulness Remote isn't connected to its helper right now. Please try again in a moment."
    }

    /// The QR code for STATE.setupURL (cached; the URL contains the one-time setup secret and
    /// is never logged or copied anywhere).
    func setupQRCode() -> NSImage? {
        qrCode(for: state.setupURL)
    }

    /// The QR code for STATE.joinURL ("Add this Mac to your account"; same rules as the setup code).
    func joinQRCode() -> NSImage? {
        qrCode(for: state.joinURL)
    }

    private func qrCode(for url: String?) -> NSImage? {
        guard let url else { return nil }
        if let cached = qrCache, cached.text == url { return cached.image }
        guard let image = QRCode.image(for: url, pointSize: 240) else { return nil }
        qrCache = (text: url, image: image)
        return image
    }

    /// "Connect to another Mac…": opens the server's web page in the default browser. Every Mac
    /// can also be a controller — the browser client signs in with the owner's passkey.
    func openWebClient() {
        guard !settings.serverURL.isEmpty, let url = URL(string: settings.serverURL) else {
            notice = "First type your server address (Dashboard → Settings)."
            return
        }
        if !NSWorkspace.shared.open(url) {
            notice = "Your web browser could not be opened. Open \(serverDisplayName) in it yourself."
        }
    }

    // MARK: Settings

    /// Validates and saves the server address. Returns an error message for the owner, or nil.
    func setServerAddress(_ text: String) -> String? {
        switch ServerAddress.normalize(text) {
        case .failure(let error):
            return error.message
        case .success(let origin):
            if origin != settings.serverURL {
                settings.serverURL = origin
            } else if !agentRunning {
                startAgentIfPossible()
            }
            return nil
        }
    }

    private func settingsDidChange(from old: HostSettings) {
        AppModel.saveSettings(settings)
        guard settings != old else { return }
        if settings.serverURL != old.serverURL {
            restartAgent()
            return
        }
        if settings.agentSettings != old.agentSettings, agentRunning {
            agent.send(command: .settings(settings.agentSettings))
        }
    }

    private static func loadSettings() -> HostSettings {
        guard let data = UserDefaults.standard.data(forKey: Keys.settings),
              let saved = try? JSONDecoder().decode(HostSettings.self, from: data) else {
            return HostSettings()
        }
        return saved
    }

    private static func saveSettings(_ settings: HostSettings) {
        if let data = try? HRJSON.encode(settings) {
            UserDefaults.standard.set(data, forKey: Keys.settings)
        }
    }

    // MARK: Setup wizard

    func openSetup(steps: [WizardStep] = WizardStep.allCases, notice: String? = nil) {
        WindowManager.shared.showWizard(steps: steps, notice: notice)
    }

    /// The full wizard was finished.
    func completeSetup() {
        UserDefaults.standard.removeObject(forKey: Keys.wizardStep)
        if !settings.setupCompleted { settings.setupCompleted = true }
    }

    /// The wizard window closed (finished or not). Once a server address is saved, the wizard
    /// no longer opens by itself; "Show setup again" stays available in Settings.
    func wizardClosed() {
        if !settings.setupCompleted && !settings.serverURL.isEmpty {
            settings.setupCompleted = true
        }
    }

    var savedWizardStep: WizardStep? {
        guard let raw = UserDefaults.standard.object(forKey: Keys.wizardStep) as? Int else { return nil }
        return WizardStep(rawValue: raw)
    }

    func saveWizardStep(_ step: WizardStep) {
        UserDefaults.standard.set(step.rawValue, forKey: Keys.wizardStep)
    }

    // MARK: Permissions

    func refreshPermissions() {
        let screen = Permissions.screenRecording
        let accessibility = Permissions.accessibility
        if screenRecordingAllowed != screen { screenRecordingAllowed = screen }
        if accessibilityAllowed != accessibility { accessibilityAllowed = accessibility }
        if accessibility && inputBlockedByPermission { inputBlockedByPermission = false }
        if screen && captureProblem != nil && state.session == nil { captureProblem = nil }
        notifier.authorizationStatus { allowed in
            onMain { AppModel.shared.setNotificationsAllowed(allowed) }
        }
    }

    private func setNotificationsAllowed(_ allowed: Bool?) {
        if notificationsAllowed != allowed { notificationsAllowed = allowed }
    }

    /// The first time, macOS shows its own prompt (with an "Open System Settings" button);
    /// after that the request does nothing visible, so open the settings pane directly.
    func requestScreenRecording() {
        let askedKey = "hr.askedScreenRecording"
        let askedBefore = UserDefaults.standard.bool(forKey: askedKey)
        UserDefaults.standard.set(true, forKey: askedKey)
        if !Permissions.requestScreenRecording() && askedBefore {
            Permissions.open(.screenRecording)
        }
        refreshPermissions()
    }

    func requestAccessibility() {
        Permissions.requestAccessibility()
        refreshPermissions()
    }

    /// Shows the macOS prompt; if notifications were already turned off (no prompt appears
    /// any more), opens Notification settings instead.
    func requestNotifications() {
        if notificationsAllowed == false {
            Permissions.open(.notifications)
            return
        }
        notifier.requestAuthorization { granted in
            onMain { AppModel.shared.setNotificationsAllowed(granted) }
        }
    }

    /// Windows that show permission state call begin/end; while any is open, permissions and
    /// the login item are re-read every second.
    func beginPermissionPolling() {
        pollers += 1
        guard pollTask == nil else { return }
        pollTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                self?.refreshPermissions()
                self?.refreshLoginItem()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    func endPermissionPolling() {
        pollers = max(0, pollers - 1)
        if pollers == 0 {
            pollTask?.cancel()
            pollTask = nil
        }
    }

    /// Some permissions (Screen Recording) only take effect after the app restarts.
    func relaunch() {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { _, error in
            if let error {
                Log.app.error("Relaunch failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 300_000_000)
            NSApp.terminate(nil)
        }
    }

    // MARK: Launch at login

    func refreshLoginItem() {
        let enabled = LoginItem.isEnabled
        let needsApproval = LoginItem.needsApproval
        if launchAtLoginEnabled != enabled { launchAtLoginEnabled = enabled }
        if loginItemNeedsApproval != needsApproval { loginItemNeedsApproval = needsApproval }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        loginItemMessage = LoginItem.setEnabled(enabled)
        refreshLoginItem()
        objectWillChange.send()
    }

    // MARK: Firewall

    func refreshFirewall() {
        DispatchQueue.global(qos: .utility).async {
            let current = FirewallControl.readState()
            onMain { AppModel.shared.setFirewall(current) }
        }
    }

    private func setFirewall(_ value: FirewallState) {
        if firewall != value { firewall = value }
    }

    /// One macOS password prompt: firewall on, stealth mode on, app + helper allowed.
    func enableFirewall() {
        guard !firewallBusy else { return }
        firewallBusy = true
        firewallMessage = "Waiting for your Mac password…"
        Task { @MainActor [weak self] in
            // Let the window show the message before the (blocking) password dialog appears.
            try? await Task.sleep(nanoseconds: 150_000_000)
            let result = FirewallControl.enableWithAdminPrompt()
            guard let self else { return }
            self.firewallBusy = false
            self.firewallMessage = result.ok ? "The firewall and stealth mode are on." : result.message
            self.refreshFirewall()
        }
    }

    // MARK: Displays

    private func observeScreens() {
        guard screenObserver == nil else { return }
        screenObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification,
            object: nil,
            queue: .main
        ) { _ in
            onMain { AppModel.shared.sendDisplays() }
        }
    }

    /// COMMAND displays: the agent forwards the list to clients (control "hello") and uses
    /// `active` for new sessions.
    func sendDisplays() {
        guard agentRunning else { return }
        let list = DisplayCatalog.current()
        guard let first = list.first else { return }
        let active: CGDirectDisplayID
        if list.contains(where: { $0.id == activeDisplayID }) {
            active = activeDisplayID
        } else {
            active = list.first(where: { $0.primary })?.id ?? first.id
        }
        agent.send(command: .displays(list: list, active: active))
    }

    // MARK: Quit

    /// Ends any session, stops the helper (so it can log the session end and close its files),
    /// then lets the app terminate.
    func prepareForQuit() {
        if quitting { return }
        quitting = true
        restartTask?.cancel()
        pollTask?.cancel()
        endSessionLocally()
        hotKey.unregister()
        agentRunning = false
        agent.stop {
            onMain { NSApp.reply(toApplicationShouldTerminate: true) }
        }
    }
}
