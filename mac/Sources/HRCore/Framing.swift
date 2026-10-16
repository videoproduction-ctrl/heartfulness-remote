import Foundation

/// IPC frame types between the Swift app and the `hr-agent` helper (PROTOCOL.md §9).
public enum IPCType: UInt8, Sendable, CaseIterable {
    // Swift → agent
    case config = 0x01
    case signResult = 0x02
    case video = 0x03
    case audio = 0x04
    case command = 0x05
    // agent → Swift
    case signRequest = 0x81
    case state = 0x82
    case input = 0x83
    case encoder = 0x84
    case audioControl = 0x85
    case clipboardSet = 0x86
    case event = 0x87
    case log = 0x88
}

/// One decoded frame: `u32be(len) ‖ u8 type ‖ payload`, where len counts type + payload.
public struct IPCFrame: Equatable, Sendable {
    public var type: UInt8
    public var payload: Data

    public init(type: UInt8, payload: Data) {
        self.type = type
        self.payload = payload
    }

    public init(_ type: IPCType, payload: Data) {
        self.type = type.rawValue
        self.payload = payload
    }

    public var knownType: IPCType? { IPCType(rawValue: type) }
}

public enum FramingError: Error, Equatable {
    /// The length prefix is 0 (no type byte) or larger than `IPCFraming.maxFrameLength`.
    case invalidLength(Int)
}

public enum IPCFraming {
    /// Maximum value of the length prefix (type byte + payload): 16 MiB.
    public static let maxFrameLength = 16 * 1024 * 1024
    /// Size of the length prefix.
    public static let headerSize = 4

    /// Encodes a frame. Throws if the payload is too large.
    public static func encode(type: UInt8, payload: Data) throws -> Data {
        let length = payload.count + 1
        guard length <= maxFrameLength else { throw FramingError.invalidLength(length) }
        var out = Data(capacity: headerSize + length)
        BigEndian.append(UInt32(length), to: &out)
        out.append(type)
        out.append(payload)
        return out
    }

    public static func encode(_ type: IPCType, payload: Data) throws -> Data {
        try encode(type: type.rawValue, payload: payload)
    }
}

/// Incremental decoder for a byte stream of frames. Feed it whatever `read()` returns;
/// it returns every complete frame and keeps partial data for the next call.
/// After it throws, the stream is out of sync and must be discarded.
public struct FrameDecoder {
    private var buffer: [UInt8] = []
    private var readIndex = 0

    public init() {}

    /// Number of buffered bytes that do not yet form a complete frame.
    public var pendingByteCount: Int { buffer.count - readIndex }

    public mutating func append(_ data: Data) throws -> [IPCFrame] {
        buffer.append(contentsOf: data)
        var frames: [IPCFrame] = []
        while buffer.count - readIndex >= IPCFraming.headerSize {
            let b0 = Int(buffer[readIndex])
            let b1 = Int(buffer[readIndex + 1])
            let b2 = Int(buffer[readIndex + 2])
            let b3 = Int(buffer[readIndex + 3])
            let length = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
            if length < 1 || length > IPCFraming.maxFrameLength {
                throw FramingError.invalidLength(length)
            }
            let available = buffer.count - readIndex - IPCFraming.headerSize
            if available < length { break }
            let typeIndex = readIndex + IPCFraming.headerSize
            let payloadStart = typeIndex + 1
            let payloadEnd = typeIndex + length
            let payload = Data(buffer[payloadStart..<payloadEnd])
            frames.append(IPCFrame(type: buffer[typeIndex], payload: payload))
            readIndex = payloadEnd
        }
        compact()
        return frames
    }

    private mutating func compact() {
        if readIndex == 0 { return }
        if readIndex >= buffer.count {
            buffer.removeAll(keepingCapacity: true)
            readIndex = 0
        } else if readIndex > 1 << 20 {
            buffer.removeFirst(readIndex)
            readIndex = 0
        }
    }
}

/// Big-endian helpers.
public enum BigEndian {
    public static func append(_ value: UInt32, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 24))
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    public static func append(_ value: UInt64, to data: inout Data) {
        var shift: UInt64 = 56
        while true {
            data.append(UInt8(truncatingIfNeeded: value >> shift))
            if shift == 0 { break }
            shift -= 8
        }
    }

    public static func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= bytes.count else { return nil }
        var v: UInt32 = 0
        for i in 0..<4 { v = (v << 8) | UInt32(bytes[offset + i]) }
        return v
    }

    public static func readUInt64(_ bytes: [UInt8], at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= bytes.count else { return nil }
        var v: UInt64 = 0
        for i in 0..<8 { v = (v << 8) | UInt64(bytes[offset + i]) }
        return v
    }
}

/// Codec byte of VIDEO frames.
public enum VideoCodecID: UInt8, Sendable {
    case h264 = 1
    case h265 = 2
}

/// Binary payloads for VIDEO (0x03) and AUDIO (0x04) frames.
public enum MediaPayload {
    /// `u8 codec ‖ u8 flags (bit0 keyframe) ‖ u64be pts_us ‖ Annex-B access unit`
    public static func video(codec: VideoCodecID, keyframe: Bool, ptsMicros: UInt64, accessUnit: Data) -> Data {
        var out = Data(capacity: 10 + accessUnit.count)
        out.append(codec.rawValue)
        out.append(keyframe ? 0x01 : 0x00)
        BigEndian.append(ptsMicros, to: &out)
        out.append(accessUnit)
        return out
    }

    /// `u64be pts_us ‖ Opus packet`
    public static func audio(ptsMicros: UInt64, packet: Data) -> Data {
        var out = Data(capacity: 8 + packet.count)
        BigEndian.append(ptsMicros, to: &out)
        out.append(packet)
        return out
    }

    public struct DecodedVideo: Equatable {
        public var codec: UInt8
        public var keyframe: Bool
        public var ptsMicros: UInt64
        public var accessUnit: Data
    }

    /// Parses a VIDEO payload (used by tests and diagnostics).
    public static func decodeVideo(_ payload: Data) -> DecodedVideo? {
        let bytes = [UInt8](payload)
        guard bytes.count >= 10, let pts = BigEndian.readUInt64(bytes, at: 2) else { return nil }
        return DecodedVideo(codec: bytes[0], keyframe: bytes[1] & 0x01 != 0, ptsMicros: pts, accessUnit: Data(bytes[10...]))
    }
}
