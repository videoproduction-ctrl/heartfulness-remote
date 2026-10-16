import Foundation

/// base64url without padding (PROTOCOL.md §2: all binary values in JSON).
public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        while s.hasSuffix("=") { s.removeLast() }
        return s
    }

    public static func encode(_ bytes: [UInt8]) -> String { encode(Data(bytes)) }

    /// Decodes base64url (padding optional). Returns nil for invalid input.
    public static func decode(_ string: String) -> Data? {
        var s = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.contains("+") || s.contains("/") { return nil }
        s = s.replacingOccurrences(of: "-", with: "+")
        s = s.replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 { s += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: s)
    }
}

/// RFC 4648 base32, lowercase, no padding.
public enum Base32 {
    private static let alphabet: [Character] = Array("abcdefghijklmnopqrstuvwxyz234567")

    public static func encodeLowercaseNoPadding(_ bytes: [UInt8]) -> String {
        var out = ""
        var buffer: UInt32 = 0
        var bits = 0
        for byte in bytes {
            buffer = ((buffer << 8) | UInt32(byte)) & 0xFFFF
            bits += 8
            while bits >= 5 {
                let index = Int((buffer >> UInt32(bits - 5)) & 0x1F)
                out.append(alphabet[index])
                bits -= 5
            }
        }
        if bits > 0 {
            let index = Int((buffer << UInt32(5 - bits)) & 0x1F)
            out.append(alphabet[index])
        }
        return out
    }
}

/// Human-readable key fingerprint (PROTOCOL.md §2):
/// lowercase base32 of SHA-256(pub)[0:10], groups of 4 joined by "-".
/// HRCore stays Foundation-only, so the caller supplies the SHA-256 digest (CryptoKit).
public enum Fingerprint {
    public static func format(sha256Digest digest: [UInt8]) -> String {
        let text = Base32.encodeLowercaseNoPadding(Array(digest.prefix(10)))
        var groups: [String] = []
        var current = ""
        for ch in text {
            current.append(ch)
            if current.count == 4 {
                groups.append(current)
                current = ""
            }
        }
        if !current.isEmpty { groups.append(current) }
        return groups.joined(separator: "-")
    }
}

/// Short authentication string helpers (PROTOCOL.md §3).
public enum SASFormatter {
    /// "123456" → "123 456". Anything that is not exactly six digits is returned unchanged.
    public static func format(_ raw: String) -> String {
        guard let parts = groups(raw) else { return raw }
        return parts.0 + " " + parts.1
    }

    /// Splits a SAS into its two 3-digit halves, ignoring spaces.
    public static func groups(_ raw: String) -> (String, String)? {
        let digits = raw.filter { $0 != " " }
        guard digits.count == 6, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return (String(digits.prefix(3)), String(digits.suffix(3)))
    }

    /// Zero-pads a numeric SAS to six digits.
    public static func zeroPadded(_ value: Int) -> String {
        let v = abs(value) % 1_000_000
        let s = String(v)
        return String(repeating: "0", count: max(0, 6 - s.count)) + s
    }

    /// SAS from SHA-256(TBS("HR1/sas", hostPub, devicePub, nd, na)):
    /// `u32be(digest[0:4]) mod 1_000_000`, zero-padded. (The caller computes the digest.)
    public static func code(fromDigest digest: [UInt8]) -> String? {
        guard let v = BigEndian.readUInt32(digest, at: 0) else { return nil }
        return zeroPadded(Int(v % 1_000_000))
    }
}

/// Mac ID helpers (PROTOCOL.md §10.1): a 9-digit display number for a host key,
/// `u32be(SHA-256(TBS("HR1/mac-id", hostPub))[0:4]) mod 10^9`, shown "482 913 557".
/// It is only a name to type or read out — never used to decide trust.
public enum MacIDFormatter {
    public static let label = "HR1/mac-id"

    /// "482913557" → "482 913 557". Anything that is not exactly nine digits is returned unchanged.
    public static func format(_ raw: String) -> String {
        guard let digits = digits(raw) else { return raw }
        let chars = Array(digits)
        return String(chars[0..<3]) + " " + String(chars[3..<6]) + " " + String(chars[6..<9])
    }

    /// The nine digits of a Mac ID, ignoring spaces and dashes; nil if it isn't one.
    public static func digits(_ raw: String) -> String? {
        let digits = raw.filter { $0 != " " && $0 != "-" }
        guard digits.count == 9, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return digits
    }

    /// The bytes to hash with SHA-256 (the caller hashes with CryptoKit; HRCore is Foundation-only).
    public static func transcript(hostPub: Data) -> Data {
        TBS.build(label: label, fields: [hostPub])
    }

    /// The Mac ID from SHA-256(transcript): nine digits, zero-padded, no spaces.
    public static func code(fromDigest digest: [UInt8]) -> String? {
        guard let v = BigEndian.readUInt32(digest, at: 0) else { return nil }
        let s = String(v % 1_000_000_000)
        return String(repeating: "0", count: max(0, 9 - s.count)) + s
    }
}

/// Signature transcript encoding (PROTOCOL.md §3):
/// `UTF8(label) || 0x00 || Σ(u32be(len(f)) || f)`.
public enum TBS {
    public static func build(label: String, fields: [Data]) -> Data {
        var out = Data(label.utf8)
        out.append(0)
        for field in fields {
            BigEndian.append(UInt32(field.count), to: &out)
            out.append(field)
        }
        return out
    }

    /// Extracts the label of a transcript (bytes before the first 0x00).
    public static func label(of tbs: Data) -> String? {
        let bytes = [UInt8](tbs.prefix(65))
        guard let zero = bytes.firstIndex(of: 0), zero > 0 else { return nil }
        return String(bytes: bytes[0..<zero], encoding: .utf8)
    }

    /// Splits a transcript into label + fields; nil if malformed.
    public static func parse(_ tbs: Data) -> (label: String, fields: [Data])? {
        let bytes = [UInt8](tbs)
        guard let zero = bytes.firstIndex(of: 0), zero > 0,
              let label = String(bytes: bytes[0..<zero], encoding: .utf8) else { return nil }
        var fields: [Data] = []
        var i = zero + 1
        while i < bytes.count {
            guard let len32 = BigEndian.readUInt32(bytes, at: i) else { return nil }
            let len = Int(len32)
            i += 4
            guard len <= bytes.count - i else { return nil }
            fields.append(Data(bytes[i..<(i + len)]))
            i += len
        }
        return (label, fields)
    }
}

/// Which transcripts the host key may sign on the agent's behalf.
/// PROTOCOL.md §3: the host signs host-auth, pair-challenge, cert, revoked and answer —
/// nothing else. Refusing other labels limits what a compromised helper could make the
/// Mac's identity key sign.
public enum SigningPolicy {
    public static let allowedLabels: Set<String> = [
        "HR1/host-auth",
        "HR1/pair-challenge",
        "HR1/cert",
        "HR1/revoked",
        "HR1/answer",
    ]

    public static func isAllowed(_ tbs: Data) -> Bool {
        guard let parsed = TBS.parse(tbs) else { return false }
        return allowedLabels.contains(parsed.label)
    }
}
