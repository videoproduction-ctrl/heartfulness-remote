import Foundation

// Plain-language text for the owner (a media producer, not a developer).
// Kept in HRCore (Foundation only) so it is unit-tested; the SwiftUI views only
// choose symbols and colours.

// MARK: - Big status

/// What the menu bar icon, the menu panel and the dashboard show in large type.
public struct HostStatusSummary: Equatable, Sendable {
    public enum Kind: String, Equatable, Sendable {
        /// Connected to the server, waiting for an approved device.
        case online
        /// Not connected to the server (connecting, offline, server error, not set up).
        case offline
        /// A remote session is active.
        case connected
        /// The kill switch is on.
        case blocked
        /// Something needs the owner (identity unreadable, trust store tampered, helper broken).
        case attention
    }

    public var kind: Kind
    public var title: String
    public var detail: String

    public init(kind: Kind, title: String, detail: String) {
        self.kind = kind
        self.title = title
        self.detail = detail
    }

    public static let offlineTitle = "Offline — not connected to your server"

    /// - Parameters:
    ///   - state: the latest STATE from the agent (or a default one)
    ///   - agentRunning: whether hr-agent is running
    ///   - serverAddress: the configured origin ("" = not set up yet)
    ///   - problem: a local problem that blocks everything (identity / helper), if any
    public static func make(state: AgentState, agentRunning: Bool, serverAddress: String,
                            problem: String? = nil) -> HostStatusSummary {
        if let problem, !problem.isEmpty {
            return HostStatusSummary(kind: .attention, title: "Needs your attention", detail: problem)
        }
        let serverName = ServerAddress.displayName(serverAddress)
        if serverAddress.isEmpty {
            return HostStatusSummary(kind: .offline, title: offlineTitle,
                                     detail: "Finish the setup: type your server address.")
        }
        if !agentRunning {
            return HostStatusSummary(kind: .offline, title: offlineTitle, detail: "Starting…")
        }
        if state.server == .error, let code = state.serverError, ServerErrorText.isTrustStoreProblem(code) {
            return HostStatusSummary(kind: .attention, title: "Connections refused for safety",
                                     detail: ServerErrorText.message(for: code))
        }
        if state.killed {
            return HostStatusSummary(kind: .blocked, title: "Connections blocked",
                                     detail: "Nobody can connect until you allow connections again.")
        }
        if let session = state.session {
            return HostStatusSummary(kind: .connected, title: "\(session.device.displayName) is connected",
                                     detail: "They can see and control this Mac. Click “Disconnect now” to end it.")
        }
        switch state.server {
        case .online:
            switch state.account {
            case .serverNotSetUp:
                return HostStatusSummary(kind: .online, title: "Your Mac is ready",
                                         detail: "One more step: pair your phone (see the setup window).")
            case .notInAccount:
                return HostStatusSummary(kind: .online, title: "Almost ready",
                                         detail: "One more step: add this Mac to your account.")
            case .inAccount:
                return HostStatusSummary(kind: .online, title: "Your Mac is ready",
                                         detail: "Approved devices can connect through \(serverName).")
            }
        case .connecting:
            return HostStatusSummary(kind: .offline, title: offlineTitle, detail: "Connecting to \(serverName)…")
        case .offline:
            return HostStatusSummary(kind: .offline, title: offlineTitle,
                                     detail: "Trying again automatically. Check that this Mac is connected to the internet.")
        case .error:
            return HostStatusSummary(kind: .offline, title: offlineTitle,
                                     detail: ServerErrorText.message(for: state.serverError ?? ""))
        }
    }
}

// MARK: - Server / agent error codes

/// STATE.serverError codes: from the server (`{type:"error", code}` on /ws/host) or the agent itself.
public enum ServerErrorText {
    public static func isTrustStoreProblem(_ code: String) -> Bool {
        code.hasPrefix("trust-store")
    }

    public static func message(for code: String) -> String {
        switch code {
        case "already-claimed":
            return "Your server is already set up with a different Mac and doesn't accept more Macs yet. Update your server to the latest version — or, if this is your only Mac, reset the server (see “Fix offline” in the user guide)."
        case "host-not-allowed":
            return "Your server is set to accept only a different Mac."
        case "bad-signature":
            return "Your server could not confirm this Mac's identity. Trying again automatically."
        case "too-many-pending":
            return "Too many Macs are waiting to be set up on your server. Restart the server, then try again."
        case "replaced":
            return "Another copy of Heartfulness Remote with the same identity connected to your server."
        case "rate-limited":
            return "Your server asked this Mac to slow down. Trying again shortly."
        case "auth-timeout":
            return "Your server took too long to answer. Trying again automatically."
        case "trust-store-tampered":
            return "The list of approved devices on this Mac was changed outside Heartfulness Remote, so every connection is refused. If you didn't expect this, ask for help. Otherwise choose “Start fresh” in Settings and pair your devices again."
        case "trust-store-host-mismatch":
            return "The list of approved devices belongs to a different identity of this Mac, so every connection is refused. Choose “Start fresh” in Settings and pair your devices again."
        case "trust-store-error":
            return "The list of approved devices could not be opened, so every connection is refused. Restart your Mac; if that doesn't help, choose “Start fresh” in Settings."
        case "":
            return "Your server reported a problem. Trying again automatically."
        default:
            return "Your server reported a problem (\(code)). Trying again automatically."
        }
    }
}

// MARK: - Your account (several Macs)

/// Plain-language text for adding this Mac to the owner's account (PROTOCOL.md §10).
public enum AccountText {
    /// "Mac ID 482 913 557", or nil while the ID isn't known.
    public static func macIDLine(_ macId: String) -> String? {
        guard MacIDFormatter.digits(macId) != nil else { return nil }
        return "Mac ID " + MacIDFormatter.format(macId)
    }

    public static let addTitle = "Add this Mac to your account"
    public static let addSubtitle = "Your server already has an owner. To use this Mac from your other devices, add it to your account once — from a phone or computer you already use with Heartfulness Remote."
    public static let scanSteps = [
        "On your phone, open the Camera app and scan this code.",
        "Tap the link that appears. Your phone must already be signed in to Heartfulness Remote.",
        "Confirm with your passkey (Face ID, Touch ID or fingerprint).",
        "This page updates by itself when it's done.",
    ]
    public static let typeInstead = "Or, on any device you already use, choose “Add a Mac” and type these:"
    public static let codePrivacy = "Keep this code private. It works only once, and only for this Mac."
    public static let inAccountTitle = "This Mac is in your account ✓"
    public static func inAccountDetail(serverName: String) -> String {
        "To connect to it, open \(serverName) on any of your devices and sign in with your passkey. A device you haven't used with this Mac before asks once for your approval."
    }
    public static let connectToAnother = "Connect to Another Mac…"
    public static let connectToAnotherHelp = "Opens your Heartfulness Remote web page in your browser, where you can control your other Macs."
}

// MARK: - Sessions

public enum SessionText {
    /// Why a session ended (EVENT session-end `detail`), as the end of a sentence; nil if unknown.
    public static func endReason(_ reason: String?) -> String? {
        guard let reason, !reason.isEmpty else { return nil }
        if reason.hasPrefix("client:") { return "the other device ended it" }
        switch reason {
        case "host-disconnected": return "you disconnected it on this Mac"
        case "killed": return "connections were blocked"
        case "revoked": return "the device was removed"
        case "idle": return "there was no activity for a while"
        case "connection-failed": return "the connection was lost"
        case "connection-closed": return "the connection closed"
        case "host-shutdown": return "Heartfulness Remote stopped"
        case "browser-disabled": return "web browsers are not allowed to connect"
        case "trust-reset": return "the device list was reset"
        case "offer-timeout", "connect-timeout", "offer-rejected": return "the connection could not be set up"
        default: return nil
        }
    }

    /// "direct" / "relay" → plain text.
    public static func transport(_ transport: String?) -> String? {
        switch transport?.lowercased() {
        case "direct": return "Direct connection"
        case "relay": return "Through your relay server"
        default: return nil
        }
    }

    /// "Direct connection · 12 ms"
    public static func connectionLine(_ session: SessionInfo) -> String {
        var parts: [String] = []
        if let t = transport(session.transport) { parts.append(t) }
        if let rtt = session.rttMs, rtt > 0 { parts.append("\(Int(rtt.rounded())) ms") }
        if let codec = session.codec {
            parts.append(codec.lowercased() == "h265" ? "HEVC" : (codec.lowercased() == "h264" ? "H.264" : codec))
        }
        return parts.joined(separator: " · ")
    }

    /// 75 → "1 min", 3725 → "1 h 2 min", 20 → "20 s"
    public static func duration(seconds: Int) -> String {
        let s = max(0, seconds)
        if s < 60 { return "\(s) s" }
        let minutes = s / 60
        if minutes < 60 { return "\(minutes) min" }
        let hours = minutes / 60
        let rest = minutes % 60
        return rest == 0 ? "\(hours) h" : "\(hours) h \(rest) min"
    }
}

// MARK: - Devices

public enum DeviceKindText {
    /// Device "kind" from pairing ("browser", "app", …) → plain text.
    public static func label(_ kind: String) -> String {
        switch kind.lowercased() {
        case "browser": return "Web browser"
        case "app", "tauri", "native", "desktop": return "Heartfulness Remote app"
        default: return "Device"
        }
    }

    /// Matches the agent's IsBrowserKind: anything not explicitly native counts as a browser.
    public static func isBrowser(_ kind: String) -> Bool {
        switch kind {
        case "tauri", "native", "app", "desktop": return false
        default: return true
        }
    }
}

// MARK: - Settings text

public enum SettingsText {
    /// 30 → "30 minutes", 60 → "1 hour", 90 → "1 hour 30 minutes", 120 → "2 hours"
    public static func idle(minutes: Int) -> String {
        if minutes < 60 { return minutes == 1 ? "1 minute" : "\(minutes) minutes" }
        let hours = minutes / 60
        let rest = minutes % 60
        let h = hours == 1 ? "1 hour" : "\(hours) hours"
        return rest == 0 ? h : "\(h) \(rest) minutes"
    }

    /// 20_000 → "20 Mbit/s", 2_500 → "2.5 Mbit/s", 800 → "800 kbit/s"
    public static func bitrate(kbps: Int) -> String {
        if kbps < 1000 { return "\(kbps) kbit/s" }
        if kbps % 1000 == 0 { return "\(kbps / 1000) Mbit/s" }
        let tenths = (kbps + 50) / 100
        return "\(tenths / 10).\(tenths % 10) Mbit/s"
    }
}

// MARK: - Notifications for agent events

public struct EventNotification: Equatable, Sendable {
    public var title: String
    public var body: String
    /// Clicking it should open the Approvals page.
    public var isPairing: Bool
    /// A stable identifier so a newer notification replaces an older one of the same kind.
    public var identifier: String

    public init(title: String, body: String, isPairing: Bool = false, identifier: String) {
        self.title = title
        self.body = body
        self.isPairing = isPairing
        self.identifier = identifier
    }

    /// The notification to show for an EVENT frame, or nil for events that need none.
    public static func make(for event: AgentEvent) -> EventNotification? {
        let device = event.deviceName
        let detail = event.detailText
        switch event.event {
        case "session-start":
            return EventNotification(title: "\(device) connected to this Mac",
                                     body: "They can see and control your screen. Click “Disconnect” on the orange banner to end it at any time.",
                                     identifier: "hr.session")
        case "session-end":
            var body = "\(device) is no longer connected"
            if let why = SessionText.endReason(detail) { body += " (\(why))" }
            return EventNotification(title: "Session ended", body: body + ".", identifier: "hr.session")
        case "pair-request":
            var body = "“\(device)” is asking to control this Mac."
            if let code = detail { body += " Code: \(SASFormatter.format(code))." }
            body += " Approve it only if the same code is shown on that device."
            return EventNotification(title: "New device wants to connect", body: body, isPairing: true,
                                     identifier: "hr.pair.\(event.device?.pub ?? device)")
        case "device-added":
            return EventNotification(title: "Device added", body: "\(device) can now connect to this Mac.",
                                     identifier: "hr.device.\(event.device?.pub ?? device)")
        case "device-removed":
            return EventNotification(title: "Device removed", body: "\(device) can no longer connect to this Mac.",
                                     identifier: "hr.device.\(event.device?.pub ?? device)")
        case "killed":
            var body = "Nobody can connect to this Mac until you allow connections again"
            if let how = detail { body += " (blocked \(how))" }
            return EventNotification(title: "Connections blocked", body: body + ".", identifier: "hr.kill")
        case "resumed":
            var body = "Approved devices can connect to this Mac again"
            if let how = detail { body += " (allowed \(how))" }
            return EventNotification(title: "Connections allowed", body: body + ".", identifier: "hr.kill")
        case "idle-warning":
            let seconds = detail.flatMap { Int($0) }
            let when = seconds.map { "in \($0) seconds" } ?? "soon"
            return EventNotification(title: "Session ends soon",
                                     body: "No activity for a while: \(device)'s session ends \(when).",
                                     identifier: "hr.idle")
        case "file-received":
            let file = detail.map { "“\($0)”" } ?? "A file"
            return EventNotification(title: "File received",
                                     body: "\(file) from \(device) is in Downloads › Heartfulness Remote.",
                                     identifier: "hr.file.\(UUID().uuidString)")
        case "log-tampered":
            return EventNotification(title: "Access log warning",
                                     body: "The access log was changed outside Heartfulness Remote. Open Access Log for details.",
                                     identifier: "hr.security.log")
        case "trust-store-tampered", "trust-store-host-mismatch", "trust-store-error":
            return EventNotification(title: "Connections refused for safety",
                                     body: ServerErrorText.message(for: event.event),
                                     identifier: "hr.security.trust")
        case "setup-failed":
            return EventNotification(title: "Phone setup failed",
                                     body: "A device tried to finish the setup with a wrong code. If that wasn't you, nothing happened — no access was given.",
                                     identifier: "hr.setup")
        case "joined-account":
            // Same identifier as "device-added", which arrives just before: this one replaces it.
            return EventNotification(title: "This Mac is in your account",
                                     body: "\(device) added this Mac and can connect to it now. Your other devices ask once for your approval the first time they connect.",
                                     identifier: "hr.device.\(event.device?.pub ?? device)")
        case "removed-from-account":
            return EventNotification(title: "This Mac was removed from your account",
                                     body: "Your devices can't reach it through your server any more. To add it again, open Heartfulness Remote → Status.",
                                     identifier: "hr.account")
        default:
            return nil
        }
    }
}

// MARK: - Access log

public enum AccessLogText {
    public static func title(for event: String) -> String {
        switch event {
        case "session-start": return "Connected"
        case "session-end": return "Disconnected"
        case "pairing-approved", "pair-approved": return "Device approved"
        case "pairing-denied", "pair-denied": return "Device request denied"
        case "device-added": return "Device added"
        case "device-removed": return "Device removed"
        case "killed": return "Connections blocked"
        case "resumed": return "Connections allowed"
        case "file-received": return "File received"
        case "file-sent": return "File sent"
        case "trust-store-tampered": return "Warning: device list changed outside the app"
        case "log-tamper-detected": return "Warning: log changed outside the app"
        case "setup-failed": return "Phone setup failed"
        case "trust-store-reset": return "Started fresh"
        case "agent-start": return "Heartfulness Remote started"
        case "offer-rejected": return "Connection attempt refused"
        case "approval-rejected": return "Invalid approval refused"
        case "joined-account": return "Added to your account"
        case "removed-from-account": return "Removed from your account"
        default: return event
        }
    }

    public static func isWarning(_ event: String) -> Bool {
        switch event {
        case "trust-store-tampered", "log-tamper-detected", "setup-failed", "offer-rejected", "approval-rejected":
            return true
        default:
            return false
        }
    }

    public static func summary(for entry: AccessLogEntry) -> String {
        var parts: [String] = []
        if let file = entry.file {
            if let size = entry.size {
                parts.append("\(file) (\(ByteCountFormatter.string(fromByteCount: size, countStyle: .file)))")
            } else {
                parts.append(file)
            }
        }
        if let t = SessionText.transport(entry.transport) { parts.append(t) }
        if let d = entry.durationSeconds { parts.append(SessionText.duration(seconds: d)) }
        if let detail = entry.detail {
            if entry.event == "session-end", let why = SessionText.endReason(detail) {
                parts.append(why)
            } else if entry.event == "session-start", SessionText.transport(detail) != nil {
                // Same information as `transport`.
            } else {
                parts.append(detail)
            }
        }
        return parts.joined(separator: " · ")
    }
}
