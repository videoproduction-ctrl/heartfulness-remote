import Foundation

/// Any JSON value. Used for fields whose shape the protocol leaves open
/// (log entries, event details, SIGN_REQUEST ids that must be echoed verbatim).
public enum JSONValue: Codable, Equatable, Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? c.decode(Int64.self) {
            self = .int(i)
        } else if let d = try? c.decode(Double.self) {
            self = .number(d)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
        } else if let o = try? c.decode([String: JSONValue].self) {
            self = .object(o)
        } else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unsupported JSON value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .int(let i): try c.encode(i)
        case .number(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    public var stringValue: String? {
        switch self {
        case .string(let s): return s
        case .int(let i): return String(i)
        case .number(let d): return String(d)
        case .bool(let b): return b ? "true" : "false"
        default: return nil
        }
    }

    public var doubleValue: Double? {
        switch self {
        case .int(let i): return Double(i)
        case .number(let d): return d
        case .string(let s): return Double(s)
        default: return nil
        }
    }

    /// Short human-readable rendering (for log rows and notification text).
    public var displayText: String {
        switch self {
        case .null: return ""
        case .bool(let b): return b ? "yes" : "no"
        case .int(let i): return String(i)
        case .number(let d): return String(d)
        case .string(let s): return s
        case .array(let a): return a.map { $0.displayText }.filter { !$0.isEmpty }.joined(separator: ", ")
        case .object(let o):
            if let name = o["name"]?.stringValue { return name }
            return o.keys.sorted().compactMap { key -> String? in
                guard let v = o[key] else { return nil }
                let text = v.displayText
                return text.isEmpty ? nil : "\(key): \(text)"
            }.joined(separator: ", ")
        }
    }
}

/// A point in time that tolerates the encodings an agent might use:
/// unix seconds, unix milliseconds (numbers or numeric strings) or RFC 3339 strings.
public struct Timestamp: Codable, Equatable, Hashable, Comparable, Sendable {
    public var date: Date

    public init(_ date: Date) { self.date = date }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let n = try? c.decode(Double.self) {
            guard let d = Timestamp.date(fromNumber: n) else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "Invalid timestamp")
            }
            date = d
        } else if let s = try? c.decode(String.self), let d = Timestamp.date(fromString: s) {
            date = d
        } else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unsupported timestamp")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(Int64(date.timeIntervalSince1970.rounded()))
    }

    public static func < (lhs: Timestamp, rhs: Timestamp) -> Bool { lhs.date < rhs.date }

    /// Numbers above 1e11 are treated as milliseconds, otherwise seconds.
    public static func date(fromNumber n: Double) -> Date? {
        guard n.isFinite, n >= 0 else { return nil }
        return Date(timeIntervalSince1970: n > 1e11 ? n / 1000 : n)
    }

    public static func date(fromString s: String) -> Date? {
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        if let n = Double(trimmed) { return date(fromNumber: n) }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let d = plain.date(from: trimmed) { return d }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = fractional.date(from: trimmed) { return d }
        // Go's RFC3339Nano may carry more than 3 fractional digits; trim them.
        if let dot = trimmed.firstIndex(of: ".") {
            var end = trimmed.index(after: dot)
            while end < trimmed.endIndex, trimmed[end].isNumber { end = trimmed.index(after: end) }
            let digits = trimmed[trimmed.index(after: dot)..<end]
            if digits.count > 3 {
                let shortened = String(trimmed[..<trimmed.index(after: dot)]) + String(digits.prefix(3)) + String(trimmed[end...])
                return fractional.date(from: shortened)
            }
        }
        return nil
    }

    /// Lenient conversion from an arbitrary JSON value.
    public static func from(_ value: JSONValue?) -> Timestamp? {
        guard let value else { return nil }
        switch value {
        case .int(let i): return date(fromNumber: Double(i)).map { Timestamp($0) }
        case .number(let d): return date(fromNumber: d).map { Timestamp($0) }
        case .string(let s): return date(fromString: s).map { Timestamp($0) }
        default: return nil
        }
    }
}

/// Generic coding key for hand-written encoders.
public struct AnyCodingKey: CodingKey, Hashable, Sendable {
    public var stringValue: String
    public var intValue: Int? { nil }

    public init(_ string: String) { stringValue = string }
    public init?(stringValue: String) { self.stringValue = stringValue }
    public init?(intValue: Int) { return nil }
}

extension KeyedDecodingContainer {
    /// String, or a number rendered as text.
    func lenientString(_ key: Key) -> String? {
        if let s = try? decodeIfPresent(String.self, forKey: key) { return s }
        if let i = try? decodeIfPresent(Int64.self, forKey: key) { return String(i) }
        return nil
    }

    /// Integer from a JSON integer, a float, or a numeric string.
    func lenientInt(_ key: Key) -> Int? {
        if let i = try? decodeIfPresent(Int.self, forKey: key) { return i }
        if let d = try? decodeIfPresent(Double.self, forKey: key) {
            guard d.isFinite, d >= Double(Int32.min), d <= Double(Int32.max) else { return nil }
            return Int(d)
        }
        if let s = try? decodeIfPresent(String.self, forKey: key) { return Int(s.trimmingCharacters(in: .whitespaces)) }
        return nil
    }

    func lenientUInt32(_ key: Key) -> UInt32? {
        if let i = try? decodeIfPresent(UInt32.self, forKey: key) { return i }
        if let d = try? decodeIfPresent(Double.self, forKey: key) {
            guard d.isFinite, d >= 0, d <= Double(UInt32.max) else { return nil }
            return UInt32(d)
        }
        if let s = try? decodeIfPresent(String.self, forKey: key) { return UInt32(s.trimmingCharacters(in: .whitespaces)) }
        return nil
    }

    func lenientDouble(_ key: Key) -> Double? {
        if let d = try? decodeIfPresent(Double.self, forKey: key) { return d.isFinite ? d : nil }
        if let s = try? decodeIfPresent(String.self, forKey: key) { return Double(s) }
        return nil
    }

    /// Bool from `true/false`, `0/1` or `"true"/"false"`.
    func lenientBool(_ key: Key) -> Bool? {
        if let b = try? decodeIfPresent(Bool.self, forKey: key) { return b }
        if let i = try? decodeIfPresent(Int.self, forKey: key) { return i != 0 }
        if let s = try? decodeIfPresent(String.self, forKey: key) {
            switch s.lowercased() {
            case "true", "1", "yes": return true
            case "false", "0", "no": return false
            default: return nil
            }
        }
        return nil
    }

    func lenientTimestamp(_ key: Key) -> Timestamp? {
        if let t = try? decodeIfPresent(Timestamp.self, forKey: key) { return t }
        return nil
    }
}

/// Shared JSON coders with deterministic output.
public enum HRJSON {
    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try encoder().encode(value)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try JSONDecoder().decode(type, from: data)
    }
}
