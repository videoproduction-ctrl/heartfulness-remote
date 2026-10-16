import Foundation

// MARK: - Shared pieces

/// A device as the agent describes it: `{pub, name, kind}`.
/// Decoding also accepts a bare string (treated as the name).
public struct DeviceRef: Codable, Equatable, Hashable, Sendable {
    public var pub: String
    public var name: String
    public var kind: String
    /// Display fingerprint of the device key ("abcd-efgh-…"); "" if the agent sent none.
    public var fingerprint: String

    public init(pub: String = "", name: String, kind: String = "", fingerprint: String = "") {
        self.pub = pub
        self.name = name
        self.kind = kind
        self.fingerprint = fingerprint
    }

    private enum CodingKeys: String, CodingKey { case pub, name, kind, fingerprint }

    public init(from decoder: Decoder) throws {
        var pub = ""
        var name = ""
        var kind = ""
        var fingerprint = ""
        if let single = try? decoder.singleValueContainer(), let text = try? single.decode(String.self) {
            name = text
        } else {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            pub = c.lenientString(.pub) ?? ""
            name = c.lenientString(.name) ?? ""
            kind = c.lenientString(.kind) ?? ""
            fingerprint = c.lenientString(.fingerprint) ?? ""
        }
        self.pub = pub
        self.name = name
        self.kind = kind
        self.fingerprint = fingerprint
    }

    /// Name to show in the UI and notifications.
    public var displayName: String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "A device" : trimmed
    }
}

/// Server connection state reported in STATE.server.
public enum ServerConnection: String, Codable, Sendable {
    case offline
    case connecting
    case online
    case error

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = ServerConnection(rawValue: raw.lowercased()) ?? .error
    }
}

// MARK: - STATE (0x82)

public struct SessionInfo: Codable, Equatable, Sendable {
    public var device: DeviceRef
    public var since: Timestamp?
    /// "direct" | "relay"
    public var transport: String?
    public var rttMs: Double?
    /// "h264" | "h265" (Go: omitempty)
    public var codec: String?

    public init(device: DeviceRef, since: Timestamp? = nil, transport: String? = nil, rttMs: Double? = nil, codec: String? = nil) {
        self.device = device
        self.since = since
        self.transport = transport
        self.rttMs = rttMs
        self.codec = codec
    }

    private enum CodingKeys: String, CodingKey { case device, since, transport, rttMs, codec }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        device = (try? c.decodeIfPresent(DeviceRef.self, forKey: .device)) ?? DeviceRef(name: "")
        since = c.lenientTimestamp(.since)
        transport = c.lenientString(.transport).flatMap { $0.isEmpty ? nil : $0 }
        rttMs = c.lenientDouble(.rttMs)
        codec = c.lenientString(.codec).flatMap { $0.isEmpty ? nil : $0 }
    }

    public var isRelayed: Bool { transport?.lowercased() == "relay" }
}

public struct PendingApproval: Codable, Equatable, Identifiable, Sendable {
    public var requestId: String
    public var name: String
    public var kind: String
    /// Six digits, e.g. "123456" (use `SASFormatter.format` for display).
    public var sas: String
    public var expiresAt: Timestamp?

    public var id: String { requestId }

    public init(requestId: String, name: String, kind: String, sas: String, expiresAt: Timestamp? = nil) {
        self.requestId = requestId
        self.name = name
        self.kind = kind
        self.sas = sas
        self.expiresAt = expiresAt
    }

    private enum CodingKeys: String, CodingKey { case requestId, name, kind, sas, expiresAt }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        requestId = c.lenientString(.requestId) ?? ""
        name = c.lenientString(.name) ?? ""
        kind = c.lenientString(.kind) ?? ""
        if let s = try? c.decodeIfPresent(String.self, forKey: .sas) {
            sas = s
        } else if let n = try? c.decodeIfPresent(Int.self, forKey: .sas) {
            sas = SASFormatter.zeroPadded(n)
        } else {
            sas = ""
        }
        expiresAt = c.lenientTimestamp(.expiresAt)
    }

    public var displayName: String { DeviceRef(name: name, kind: kind).displayName }
}

public struct TrustedDevice: Codable, Equatable, Identifiable, Sendable {
    public var pub: String
    public var name: String
    public var kind: String
    /// Unix seconds in Go; 0 (never) decodes as nil.
    public var addedAt: Timestamp?
    public var lastUsed: Timestamp?
    /// Display fingerprint of the device key, e.g. "abcd-efgh-ijkl-mnop".
    public var fingerprint: String

    public var id: String { pub }

    public init(pub: String, name: String, kind: String, addedAt: Timestamp? = nil, lastUsed: Timestamp? = nil, fingerprint: String = "") {
        self.pub = pub
        self.name = name
        self.kind = kind
        self.addedAt = addedAt
        self.lastUsed = lastUsed
        self.fingerprint = fingerprint
    }

    private enum CodingKeys: String, CodingKey { case pub, name, kind, addedAt, lastUsed, fingerprint }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        pub = c.lenientString(.pub) ?? ""
        name = c.lenientString(.name) ?? ""
        kind = c.lenientString(.kind) ?? ""
        addedAt = c.lenientTimestamp(.addedAt)
        lastUsed = c.lenientTimestamp(.lastUsed)
        fingerprint = c.lenientString(.fingerprint) ?? ""
    }

    public var displayName: String { DeviceRef(name: name, kind: kind).displayName }
}

/// STATE payload:
/// `{server, serverError?, claimed, setupURL?, killed, session, pending, devices}`.
public struct AgentState: Codable, Equatable, Sendable {
    public var server: ServerConnection
    public var serverError: String?
    public var claimed: Bool
    public var setupURL: String?
    public var killed: Bool
    public var session: SessionInfo?
    public var pending: [PendingApproval]
    public var devices: [TrustedDevice]

    public init(server: ServerConnection = .offline, serverError: String? = nil, claimed: Bool = false,
                setupURL: String? = nil, killed: Bool = false, session: SessionInfo? = nil,
                pending: [PendingApproval] = [], devices: [TrustedDevice] = []) {
        self.server = server
        self.serverError = serverError
        self.claimed = claimed
        self.setupURL = setupURL
        self.killed = killed
        self.session = session
        self.pending = pending
        self.devices = devices
    }

    private enum CodingKeys: String, CodingKey {
        case server, serverError, claimed, setupURL, killed, session, pending, devices
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        server = (try? c.decodeIfPresent(ServerConnection.self, forKey: .server)) ?? .offline
        serverError = c.lenientString(.serverError).flatMap { $0.isEmpty ? nil : $0 }
        claimed = c.lenientBool(.claimed) ?? false
        setupURL = c.lenientString(.setupURL).flatMap { $0.isEmpty ? nil : $0 }
        killed = c.lenientBool(.killed) ?? false
        session = try? c.decodeIfPresent(SessionInfo.self, forKey: .session)
        pending = (try? c.decodeIfPresent([PendingApproval].self, forKey: .pending)) ?? []
        devices = (try? c.decodeIfPresent([TrustedDevice].self, forKey: .devices)) ?? []
    }
}

// MARK: - EVENT (0x87)

public enum AgentEventName: String, Sendable {
    case sessionStart = "session-start"
    case sessionEnd = "session-end"
    case pairRequest = "pair-request"
    case deviceAdded = "device-added"
    case deviceRemoved = "device-removed"
    case killed = "killed"
    case resumed = "resumed"
    case idleWarning = "idle-warning"
    case fileReceived = "file-received"
}

/// `{event, device?, detail?}` — `device` may be an object or a plain name.
public struct AgentEvent: Codable, Equatable, Sendable {
    public var event: String
    public var device: DeviceRef?
    public var detail: JSONValue?

    public init(event: String, device: DeviceRef? = nil, detail: JSONValue? = nil) {
        self.event = event
        self.device = device
        self.detail = detail
    }

    private enum CodingKeys: String, CodingKey { case event, device, detail }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        event = c.lenientString(.event) ?? ""
        device = try? c.decodeIfPresent(DeviceRef.self, forKey: .device)
        detail = try? c.decodeIfPresent(JSONValue.self, forKey: .detail)
    }

    public var name: AgentEventName? { AgentEventName(rawValue: event) }
    public var deviceName: String { device?.displayName ?? "A device" }
    public var detailText: String? {
        guard let detail else { return nil }
        let text = detail.displayText
        return text.isEmpty ? nil : text
    }
}

// MARK: - ENCODER (0x84)

public enum H264Profile: String, Sendable {
    case high
    case baseline
}

public enum EncoderAction: Equatable, Sendable {
    case start(codec: VideoCodecID, fps: Int, kbps: Int, display: UInt32?, profile: H264Profile)
    case stop
    case keyframe
    case bitrate(kbps: Int)
    case display(id: UInt32)
    case unknown(String)
}

/// `{cmd:"start", codec, fps, kbps, display, profile?}` | `{cmd:"stop"}` | `{cmd:"keyframe"}` |
/// `{cmd:"bitrate", kbps}` | `{cmd:"display", id}`
public struct EncoderCommand: Decodable, Equatable, Sendable {
    public static let defaultFPS = 60
    public static let defaultKbps = 12_000

    public var cmd: String
    public var codec: VideoCodecID?
    public var fps: Int?
    public var kbps: Int?
    public var display: UInt32?
    public var id: UInt32?
    public var profile: H264Profile?

    private enum CodingKeys: String, CodingKey { case cmd, codec, fps, kbps, display, id, profile }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cmd = (c.lenientString(.cmd) ?? "").lowercased()
        if let s = try? c.decodeIfPresent(String.self, forKey: .codec) {
            codec = EncoderCommand.codec(fromName: s)
        } else if let n = c.lenientInt(.codec) {
            codec = VideoCodecID(rawValue: UInt8(clamping: n))
        } else {
            codec = nil
        }
        fps = c.lenientInt(.fps)
        kbps = c.lenientInt(.kbps)
        display = c.lenientUInt32(.display)
        id = c.lenientUInt32(.id)
        profile = c.lenientString(.profile).flatMap { H264Profile(rawValue: $0.lowercased()) }
    }

    public static func codec(fromName name: String) -> VideoCodecID? {
        switch name.lowercased() {
        case "h264", "avc", "h.264", "avc1": return .h264
        case "h265", "hevc", "h.265", "hvc1", "hev1": return .h265
        default: return nil
        }
    }

    public var action: EncoderAction {
        switch cmd {
        case "start":
            let f = min(max(fps ?? EncoderCommand.defaultFPS, 1), 120)
            let k = min(max(kbps ?? EncoderCommand.defaultKbps, 250), 200_000)
            let d = (display ?? id).flatMap { $0 == 0 ? nil : $0 }
            return .start(codec: codec ?? .h264, fps: f, kbps: k, display: d, profile: profile ?? .high)
        case "stop":
            return .stop
        case "keyframe":
            return .keyframe
        case "bitrate":
            return .bitrate(kbps: min(max(kbps ?? EncoderCommand.defaultKbps, 250), 200_000))
        case "display":
            if let target = id ?? display { return .display(id: target) }
            return .unknown(cmd)
        default:
            return .unknown(cmd)
        }
    }
}

// MARK: - AUDIO_CTL (0x85), CLIPBOARD_SET (0x86)

public struct AudioControl: Codable, Equatable, Sendable {
    public var cmd: String
    public init(cmd: String) { self.cmd = cmd }
    public var isStart: Bool { cmd.lowercased() == "start" }
}

public struct ClipboardSet: Codable, Equatable, Sendable {
    public var text: String
    public init(text: String) { self.text = text }
}

// MARK: - INPUT (0x83)

public enum InputKind: Equatable, Sendable {
    case move, button, wheel, key, text, reset, unknown
}

/// §8.2 input message plus `display` id.
public struct InputMessage: Decodable, Equatable, Sendable {
    public var t: String
    public var x: Double?
    public var y: Double?
    public var b: Int?
    public var d: Bool?
    public var dx: Double?
    public var dy: Double?
    public var c: String?
    public var s: String?
    public var display: UInt32?

    public init(t: String, x: Double? = nil, y: Double? = nil, b: Int? = nil, d: Bool? = nil,
                dx: Double? = nil, dy: Double? = nil, c: String? = nil, s: String? = nil, display: UInt32? = nil) {
        self.t = t
        self.x = x
        self.y = y
        self.b = b
        self.d = d
        self.dx = dx
        self.dy = dy
        self.c = c
        self.s = s
        self.display = display
    }

    private enum CodingKeys: String, CodingKey { case t, x, y, b, d, dx, dy, c, s, display }

    public init(from decoder: Decoder) throws {
        let k = try decoder.container(keyedBy: CodingKeys.self)
        t = k.lenientString(.t) ?? ""
        x = k.lenientDouble(.x)
        y = k.lenientDouble(.y)
        b = k.lenientInt(.b)
        d = k.lenientBool(.d)
        dx = k.lenientDouble(.dx)
        dy = k.lenientDouble(.dy)
        c = try? k.decodeIfPresent(String.self, forKey: .c)
        s = try? k.decodeIfPresent(String.self, forKey: .s)
        display = k.lenientUInt32(.display)
    }

    public var kind: InputKind {
        switch t {
        case "m": return .move
        case "b": return .button
        case "w": return .wheel
        case "k": return .key
        case "txt": return .text
        case "reset": return .reset
        default: return .unknown
        }
    }

    /// The display this event targets, if the agent named a valid one.
    public var displayID: UInt32? { display.flatMap { $0 == 0 ? nil : $0 } }
}

// MARK: - SIGN_REQUEST (0x81) / SIGN_RESULT (0x02)

/// `{id, data}`; `data` is base64url TBS bytes. `id` is echoed back exactly as received.
public struct SignRequest: Codable, Equatable, Sendable {
    public var id: JSONValue
    public var data: String

    public init(id: JSONValue, data: String) {
        self.id = id
        self.data = data
    }
}

/// `{id, sig}` (plus `error` when the request was refused).
public struct SignResult: Codable, Equatable, Sendable {
    public var id: JSONValue
    public var sig: String
    public var error: String?

    public init(id: JSONValue, sig: String, error: String? = nil) {
        self.id = id
        self.sig = sig
        self.error = error
    }
}

// MARK: - LOG (0x88)

/// `{entries:[…], verified, error?}`
public struct LogResult: Codable, Equatable, Sendable {
    public var entries: [JSONValue]
    public var verified: Bool
    public var error: String?

    public init(entries: [JSONValue], verified: Bool, error: String? = nil) {
        self.entries = entries
        self.verified = verified
        self.error = error
    }

    private enum CodingKeys: String, CodingKey { case entries, verified, error }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        entries = (try? c.decodeIfPresent([JSONValue].self, forKey: .entries)) ?? []
        verified = c.lenientBool(.verified) ?? false
        error = c.lenientString(.error).flatMap { $0.isEmpty ? nil : $0 }
    }

    /// Entries parsed for display, newest first.
    public var displayEntries: [AccessLogEntry] {
        entries.enumerated().map { AccessLogEntry(json: $0.element, index: $0.offset) }.reversed()
    }
}

/// One access-log line as the agent writes it (agent/internal/accesslog Entry):
/// `{seq, ts, event, device?, deviceFp?, transport?, durationSec?, file?, size?, detail?, prev, mac}`.
/// Decoding is lenient so older or newer agents never break the log view.
public struct AccessLogEntry: Equatable, Identifiable, Sendable {
    /// Unique within one LOG result (the entry's `seq` when present).
    public var id: Int
    public var time: Date?
    public var event: String
    public var device: String?
    public var deviceFingerprint: String?
    public var transport: String?
    public var durationSeconds: Int?
    public var file: String?
    public var size: Int64?
    public var detail: String?

    public init(id: Int = 0, time: Date?, event: String, device: String?, detail: String?,
                deviceFingerprint: String? = nil, transport: String? = nil, durationSeconds: Int? = nil,
                file: String? = nil, size: Int64? = nil) {
        self.id = id
        self.time = time
        self.event = event
        self.device = device
        self.detail = detail
        self.deviceFingerprint = deviceFingerprint
        self.transport = transport
        self.durationSeconds = durationSeconds
        self.file = file
        self.size = size
    }

    public init(json: JSONValue, index: Int = 0) {
        guard case .object(let o) = json else {
            self.init(id: -(index + 1), time: nil, event: json.displayText, device: nil, detail: nil)
            return
        }
        func text(_ keys: [String]) -> String? {
            for key in keys {
                if let value = o[key] {
                    let t = value.displayText.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !t.isEmpty { return t }
                }
            }
            return nil
        }
        func number(_ key: String) -> Int64? {
            guard let d = o[key]?.doubleValue, d.isFinite, abs(d) < 9.0e15 else { return nil }
            return Int64(d)
        }
        let seq = number("seq")
        let timeValue = o["ts"] ?? o["time"] ?? o["at"] ?? o["timestamp"]
        let duration = number("durationSec").flatMap { $0 > 0 ? Int(clamping: $0) : nil }
        let size = number("size").flatMap { $0 > 0 ? $0 : nil }
        self.init(
            id: seq.map { Int(clamping: $0) } ?? -(index + 1),
            time: Timestamp.from(timeValue).flatMap { $0.date.timeIntervalSince1970 > 0 ? $0.date : nil },
            event: text(["event", "type", "action", "kind"]) ?? "entry",
            device: text(["device", "deviceName", "name"]),
            detail: text(["detail", "reason", "message"]),
            deviceFingerprint: text(["deviceFp"]),
            transport: text(["transport"]),
            durationSeconds: duration,
            file: text(["file"]),
            size: size
        )
    }

    /// Plain-language name of the event, e.g. "Connected".
    public var title: String { AccessLogText.title(for: event) }

    /// One line with the useful details, e.g. "through the relay · 12 min · you disconnected it".
    public var summary: String { AccessLogText.summary(for: self) }

    /// True for entries that are security warnings (shown in red).
    public var isWarning: Bool { AccessLogText.isWarning(event) }
}

// MARK: - CONFIG (0x01)

public enum CodecPreference: String, Codable, CaseIterable, Identifiable, Sendable {
    case auto
    case h264
    case h265

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .auto: return "Automatic"
        case .h264: return "H.264 (most compatible)"
        case .h265: return "HEVC (sharper, newer devices)"
        }
    }
}

/// `settings` object inside CONFIG and the `settings` COMMAND.
public struct AgentSettings: Codable, Equatable, Sendable {
    public var allowBrowserClients: Bool
    public var relayOnly: Bool
    public var idleTimeoutMin: Int
    public var maxKbps: Int
    public var codec: CodecPreference

    public init(allowBrowserClients: Bool, relayOnly: Bool, idleTimeoutMin: Int, maxKbps: Int, codec: CodecPreference) {
        self.allowBrowserClients = allowBrowserClients
        self.relayOnly = relayOnly
        self.idleTimeoutMin = idleTimeoutMin
        self.maxKbps = maxKbps
        self.codec = codec
    }
}

/// CONFIG payload — always the first frame sent after launching the agent.
public struct AgentConfig: Codable, Equatable, Sendable {
    public var serverURL: String
    /// base64url raw Ed25519 public key
    public var hostPub: String
    public var hostName: String
    public var dataDir: String
    /// base64url 32 bytes (secret — never log)
    public var storageKey: String
    public var settings: AgentSettings
    public var hevcAvailable: Bool
    public var audioAvailable: Bool

    public init(serverURL: String, hostPub: String, hostName: String, dataDir: String, storageKey: String,
                settings: AgentSettings, hevcAvailable: Bool, audioAvailable: Bool) {
        self.serverURL = serverURL
        self.hostPub = hostPub
        self.hostName = hostName
        self.dataDir = dataDir
        self.storageKey = storageKey
        self.settings = settings
        self.hevcAvailable = hevcAvailable
        self.audioAvailable = audioAvailable
    }
}

// MARK: - COMMAND (0x05)

/// One display for `COMMAND displays` (sizes are in points; `scale` = pixels per point).
public struct DisplayInfo: Codable, Equatable, Identifiable, Sendable {
    public var id: UInt32
    public var name: String
    public var width: Int
    public var height: Int
    public var scale: Double
    public var primary: Bool

    public init(id: UInt32, name: String, width: Int, height: Int, scale: Double, primary: Bool) {
        self.id = id
        self.name = name
        self.width = width
        self.height = height
        self.scale = scale
        self.primary = primary
    }
}

public enum AgentCommand: Equatable, Sendable {
    case kill
    case resume
    case disconnect
    case approve(requestId: String)
    case deny(requestId: String)
    case revoke(devicePub: String)
    case settings(AgentSettings)
    case clipboard(text: String)
    case displays(list: [DisplayInfo], active: UInt32)
    case logRead(limit: Int)
    case newSetupCode
    /// Only honoured by the agent while its trust store is unusable (tampered / foreign key):
    /// moves pins.json and the access log aside and starts afresh with a new setup code.
    case resetTrustStore
    case quit

    public var name: String {
        switch self {
        case .kill: return "kill"
        case .resume: return "resume"
        case .disconnect: return "disconnect"
        case .approve: return "approve"
        case .deny: return "deny"
        case .revoke: return "revoke"
        case .settings: return "settings"
        case .clipboard: return "clipboard"
        case .displays: return "displays"
        case .logRead: return "log-read"
        case .newSetupCode: return "new-setup-code"
        case .resetTrustStore: return "reset-trust-store"
        case .quit: return "quit"
        }
    }
}

extension AgentCommand: Encodable {
    /// Flat `{cmd, …}` objects. `settings` is sent both nested (`settings:{…}`) and flattened,
    /// so either reading of PROTOCOL §9 `settings{…}` works on the agent side.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: AnyCodingKey.self)
        try c.encode(name, forKey: AnyCodingKey("cmd"))
        switch self {
        case .kill, .resume, .disconnect, .newSetupCode, .resetTrustStore, .quit:
            break
        case .approve(let requestId), .deny(let requestId):
            try c.encode(requestId, forKey: AnyCodingKey("requestId"))
        case .revoke(let devicePub):
            try c.encode(devicePub, forKey: AnyCodingKey("devicePub"))
        case .settings(let s):
            try c.encode(s, forKey: AnyCodingKey("settings"))
            try c.encode(s.allowBrowserClients, forKey: AnyCodingKey("allowBrowserClients"))
            try c.encode(s.relayOnly, forKey: AnyCodingKey("relayOnly"))
            try c.encode(s.idleTimeoutMin, forKey: AnyCodingKey("idleTimeoutMin"))
            try c.encode(s.maxKbps, forKey: AnyCodingKey("maxKbps"))
            try c.encode(s.codec, forKey: AnyCodingKey("codec"))
        case .clipboard(let text):
            try c.encode(text, forKey: AnyCodingKey("text"))
        case .displays(let list, let active):
            try c.encode(list, forKey: AnyCodingKey("list"))
            try c.encode(active, forKey: AnyCodingKey("active"))
        case .logRead(let limit):
            try c.encode(limit, forKey: AnyCodingKey("limit"))
        }
    }
}
