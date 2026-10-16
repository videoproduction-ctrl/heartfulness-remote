import Foundation

/// macOS Application Firewall status as read from `socketfilterfw`.
public struct FirewallState: Equatable, Sendable {
    /// nil = unknown (could not be read)
    public var enabled: Bool?
    public var stealth: Bool?

    public init(enabled: Bool? = nil, stealth: Bool? = nil) {
        self.enabled = enabled
        self.stealth = stealth
    }

    public var fullyProtected: Bool { enabled == true && stealth == true }
}

/// Parses `socketfilterfw` output. Output differs between macOS versions, e.g.
/// "Firewall is enabled. (State = 1)", "Firewall is disabled. (State = 0)",
/// "Stealth mode enabled", "Firewall stealth mode is on".
public enum FirewallOutputParser {
    public static func globalState(_ output: String) -> Bool? {
        let s = output.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if s.contains("state = 0") { return false }
        if s.contains("state = 1") || s.contains("state = 2") { return true }
        return onOff(s)
    }

    public static func stealthMode(_ output: String) -> Bool? {
        onOff(output.lowercased().trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private static func onOff(_ s: String) -> Bool? {
        // Check the negative words first: "disabled" contains "enabled".
        if s.contains("disabled") || s.contains(" is off") || s.hasSuffix(" off") { return false }
        if s.contains("enabled") || s.contains(" is on") || s.hasSuffix(" on") { return true }
        return nil
    }
}

/// AppleScript source construction (string literals must be escaped).
public enum AppleScriptText {
    /// A quoted AppleScript string literal for arbitrary text.
    public static func literal(_ text: String) -> String {
        var escaped = text.replacingOccurrences(of: "\\", with: "\\\\")
        escaped = escaped.replacingOccurrences(of: "\"", with: "\\\"")
        return "\"" + escaped + "\""
    }

    public static let socketFilter = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    /// One admin-privileged script that turns on the firewall and stealth mode and allows the
    /// given executables/bundles through it. macOS shows its own password dialog.
    public static func enableFirewallScript(allowing paths: [String]) -> String {
        let fw = socketFilter
        var parts: [String] = [literal("\(fw) --setglobalstate on; \(fw) --setstealthmode on")]
        for path in paths {
            parts.append(literal("; \(fw) --add "))
            parts.append("(quoted form of " + literal(path) + ")")
            parts.append(literal("; \(fw) --unblockapp "))
            parts.append("(quoted form of " + literal(path) + ")")
        }
        return "do shell script " + parts.joined(separator: " & ") + " with administrator privileges"
    }
}
