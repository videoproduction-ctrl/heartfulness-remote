import Foundation

/// Conversion of VideoToolbox output (length-prefixed "AVCC/HVCC" NAL units) to the
/// Annex-B byte stream the agent forwards over WebRTC (start code 00 00 00 01 before each NAL).
public enum AnnexB {
    public static let startCode: [UInt8] = [0, 0, 0, 1]

    public enum ConversionError: Error, Equatable {
        case invalidLengthSize(Int)
        case truncated
    }

    /// Converts a buffer of length-prefixed NAL units.
    public static func fromLengthPrefixed(_ input: Data, lengthSize: Int = 4) throws -> Data {
        guard (1...4).contains(lengthSize) else { throw ConversionError.invalidLengthSize(lengthSize) }
        let bytes = [UInt8](input)
        var out = Data(capacity: bytes.count + 32)
        var i = 0
        while i < bytes.count {
            guard bytes.count - i >= lengthSize else { throw ConversionError.truncated }
            var length = 0
            for k in 0..<lengthSize { length = (length << 8) | Int(bytes[i + k]) }
            i += lengthSize
            guard length <= bytes.count - i else { throw ConversionError.truncated }
            if length > 0 {
                out.append(contentsOf: startCode)
                out.append(contentsOf: bytes[i..<(i + length)])
            }
            i += length
        }
        return out
    }

    /// One complete access unit: parameter sets (VPS/SPS/PPS, keyframes only) followed by
    /// the frame's NAL units, all with start codes.
    public static func accessUnit(parameterSets: [Data], lengthPrefixed: Data, lengthSize: Int = 4) throws -> Data {
        let body = try fromLengthPrefixed(lengthPrefixed, lengthSize: lengthSize)
        var out = Data(capacity: body.count + parameterSets.reduce(0) { $0 + $1.count + 4 })
        for ps in parameterSets where !ps.isEmpty {
            out.append(contentsOf: startCode)
            out.append(ps)
        }
        out.append(body)
        return out
    }

    /// Splits an Annex-B stream into NAL units (accepts 3- and 4-byte start codes).
    public static func splitNALUnits(_ stream: Data) -> [Data] {
        let b = [UInt8](stream)
        var starts: [(codeStart: Int, nalStart: Int)] = []
        var i = 0
        while i + 3 <= b.count {
            if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
                starts.append((i, i + 3))
                i += 3
            } else if i + 4 <= b.count && b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 0 && b[i + 3] == 1 {
                starts.append((i, i + 4))
                i += 4
            } else {
                i += 1
            }
        }
        var nals: [Data] = []
        for (index, s) in starts.enumerated() {
            let end = index + 1 < starts.count ? starts[index + 1].codeStart : b.count
            if end > s.nalStart { nals.append(Data(b[s.nalStart..<end])) }
        }
        return nals
    }

    /// H.264 nal_unit_type (5 = IDR, 7 = SPS, 8 = PPS).
    public static func h264Type(_ nal: Data) -> UInt8? {
        guard let first = nal.first else { return nil }
        return first & 0x1F
    }

    /// HEVC nal_unit_type (32 = VPS, 33 = SPS, 34 = PPS, 19/20 = IDR).
    public static func hevcType(_ nal: Data) -> UInt8? {
        guard let first = nal.first else { return nil }
        return (first >> 1) & 0x3F
    }
}
