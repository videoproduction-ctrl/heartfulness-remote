import Foundation

/// Everything the owner can change, persisted by the app (UserDefaults, JSON).
/// Decoding is lenient so older/newer saved versions never crash the app.
public struct HostSettings: Codable, Equatable, Sendable {
    public static let idleTimeoutRange: ClosedRange<Int> = 5...120
    public static let defaultIdleTimeoutMin = 30
    public static let idleTimeoutChoices = [5, 10, 15, 20, 30, 45, 60, 90, 120]
    public static let bitrateRange: ClosedRange<Int> = 2_000...100_000
    public static let defaultMaxKbps = 20_000
    public static let bitrateChoicesKbps = [5_000, 10_000, 20_000, 30_000, 50_000, 80_000]

    /// Normalised origin, e.g. "https://heartfulness-remote.dedyn.io" ("" = not set up yet).
    public var serverURL: String
    public var allowBrowserClients: Bool
    public var relayOnly: Bool
    public var idleTimeoutMin: Int
    public var maxKbps: Int
    public var codec: CodecPreference
    /// The first-run wizard has been completed (or dismissed) at least once.
    public var setupCompleted: Bool

    public init(serverURL: String = "",
                allowBrowserClients: Bool = true,
                relayOnly: Bool = false,
                idleTimeoutMin: Int = HostSettings.defaultIdleTimeoutMin,
                maxKbps: Int = HostSettings.defaultMaxKbps,
                codec: CodecPreference = .auto,
                setupCompleted: Bool = false) {
        self.serverURL = serverURL
        self.allowBrowserClients = allowBrowserClients
        self.relayOnly = relayOnly
        self.idleTimeoutMin = idleTimeoutMin
        self.maxKbps = maxKbps
        self.codec = codec
        self.setupCompleted = setupCompleted
    }

    private enum CodingKeys: String, CodingKey {
        case serverURL, allowBrowserClients, relayOnly, idleTimeoutMin, maxKbps, codec, setupCompleted
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = HostSettings()
        serverURL = c.lenientString(.serverURL) ?? defaults.serverURL
        allowBrowserClients = c.lenientBool(.allowBrowserClients) ?? defaults.allowBrowserClients
        relayOnly = c.lenientBool(.relayOnly) ?? defaults.relayOnly
        idleTimeoutMin = c.lenientInt(.idleTimeoutMin) ?? defaults.idleTimeoutMin
        maxKbps = c.lenientInt(.maxKbps) ?? defaults.maxKbps
        codec = c.lenientString(.codec).flatMap { CodecPreference(rawValue: $0) } ?? defaults.codec
        setupCompleted = c.lenientBool(.setupCompleted) ?? defaults.setupCompleted
        self = self.clamped()
    }

    /// Values forced into their allowed ranges.
    public func clamped() -> HostSettings {
        var s = self
        s.idleTimeoutMin = min(max(s.idleTimeoutMin, HostSettings.idleTimeoutRange.lowerBound), HostSettings.idleTimeoutRange.upperBound)
        s.maxKbps = min(max(s.maxKbps, HostSettings.bitrateRange.lowerBound), HostSettings.bitrateRange.upperBound)
        return s
    }

    /// The part of the settings the agent needs (CONFIG.settings / COMMAND settings).
    public var agentSettings: AgentSettings {
        let c = clamped()
        return AgentSettings(allowBrowserClients: c.allowBrowserClients,
                             relayOnly: c.relayOnly,
                             idleTimeoutMin: c.idleTimeoutMin,
                             maxKbps: c.maxKbps,
                             codec: c.codec)
    }
}

/// Validation and normalisation of the server address typed by the owner.
public enum ServerAddress {
    public enum ValidationError: Error, Equatable, Sendable {
        case empty
        case invalid
        case insecure
        case hasPath
        case hasCredentials

        /// Plain-language explanation for the owner.
        public var message: String {
            switch self {
            case .empty: return "Please type your server address."
            case .invalid: return "That doesn't look like a web address. Example: heartfulness-remote.dedyn.io"
            case .insecure: return "The address must be secure (https://). Just type the name, e.g. heartfulness-remote.dedyn.io"
            case .hasPath: return "Only the address is needed — remove anything after the name (like /something or ?…)."
            case .hasCredentials: return "Remove the user name or password from the address."
            }
        }
    }

    /// Accepts "name.example", "https://name.example/", "http://localhost:8080" (development).
    /// Returns the origin, e.g. "https://name.example" (lowercase host, no trailing slash).
    public static func normalize(_ input: String) -> Result<String, ValidationError> {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .failure(.empty) }
        if text.contains(" ") { return .failure(.invalid) }
        if !text.contains("://") { text = "https://" + text }
        guard let comps = URLComponents(string: text),
              let scheme = comps.scheme?.lowercased(),
              var host = comps.host?.lowercased() else {
            return .failure(.invalid)
        }
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard !host.isEmpty else { return .failure(.invalid) }
        if comps.user != nil || comps.password != nil { return .failure(.hasCredentials) }
        if comps.query != nil || comps.fragment != nil { return .failure(.hasPath) }
        if !(comps.path.isEmpty || comps.path == "/") { return .failure(.hasPath) }
        let isIPv6 = host.contains(":")
        if !isIPv6 {
            let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789.-")
            guard host.unicodeScalars.allSatisfy({ allowed.contains($0) }),
                  !host.hasPrefix("."), !host.hasPrefix("-"), !host.hasSuffix("-") else {
                return .failure(.invalid)
            }
            if host.hasSuffix(".") { host.removeLast() }
            guard host.contains(".") || isLocalhost(host) else { return .failure(.invalid) }
        }
        switch scheme {
        case "https":
            break
        case "http":
            guard isLocalhost(host) else { return .failure(.insecure) }
        default:
            return .failure(.invalid)
        }
        var origin = scheme + "://" + (isIPv6 ? "[\(host)]" : host)
        if let port = comps.port {
            guard (1...65535).contains(port) else { return .failure(.invalid) }
            let isDefault = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
            if !isDefault { origin += ":\(port)" }
        }
        return .success(origin)
    }

    public static func isLocalhost(_ host: String) -> Bool {
        let h = host.lowercased()
        return h == "localhost" || h == "127.0.0.1" || h == "::1" || h.hasSuffix(".localhost")
    }

    /// Display form without the scheme, e.g. "heartfulness-remote.dedyn.io".
    public static func displayName(_ origin: String) -> String {
        if let range = origin.range(of: "://") { return String(origin[range.upperBound...]) }
        return origin
    }
}
