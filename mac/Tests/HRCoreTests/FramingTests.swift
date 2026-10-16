import XCTest
@testable import HRCore

final class FramingTests: XCTestCase {
    func testEncodeLayout() throws {
        let frame = try IPCFraming.encode(.command, payload: Data("{}".utf8))
        XCTAssertEqual([UInt8](frame), [0, 0, 0, 3, 0x05, 0x7B, 0x7D])
    }

    func testEmptyPayloadRoundTrip() throws {
        let encoded = try IPCFraming.encode(.signResult, payload: Data())
        XCTAssertEqual([UInt8](encoded), [0, 0, 0, 1, 0x02])
        var decoder = FrameDecoder()
        let frames = try decoder.append(encoded)
        XCTAssertEqual(frames, [IPCFrame(.signResult, payload: Data())])
    }

    func testRoundTripSeveralFramesInOneChunk() throws {
        let a = IPCFrame(.state, payload: Data(#"{"server":"online"}"#.utf8))
        let b = IPCFrame(.event, payload: Data(#"{"event":"session-start"}"#.utf8))
        let c = IPCFrame(type: 0x99, payload: Data([1, 2, 3]))
        var stream = Data()
        for f in [a, b, c] { stream.append(try IPCFraming.encode(type: f.type, payload: f.payload)) }

        var decoder = FrameDecoder()
        let frames = try decoder.append(stream)
        XCTAssertEqual(frames, [a, b, c])
        XCTAssertEqual(decoder.pendingByteCount, 0)
        XCTAssertEqual(frames[0].knownType, .state)
        XCTAssertNil(frames[2].knownType)
    }

    func testSplitReadsByteByByte() throws {
        let payload = Data((0..<1000).map { UInt8($0 % 251) })
        let encoded = try IPCFraming.encode(.input, payload: payload) + IPCFraming.encode(.log, payload: Data("x".utf8))
        var decoder = FrameDecoder()
        var frames: [IPCFrame] = []
        for byte in encoded {
            frames += try decoder.append(Data([byte]))
        }
        XCTAssertEqual(frames.count, 2)
        XCTAssertEqual(frames[0], IPCFrame(.input, payload: payload))
        XCTAssertEqual(frames[1], IPCFrame(.log, payload: Data("x".utf8)))
    }

    func testSplitInsideHeaderAndPayload() throws {
        let encoded = try IPCFraming.encode(.encoder, payload: Data(#"{"cmd":"keyframe"}"#.utf8))
        var decoder = FrameDecoder()
        XCTAssertEqual(try decoder.append(encoded.prefix(2)), [])
        XCTAssertEqual(try decoder.append(encoded.subdata(in: 2..<7)), [])
        let frames = try decoder.append(encoded.subdata(in: 7..<encoded.count))
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames.first?.knownType, .encoder)
    }

    func testLargeFrameAcrossManyChunks() throws {
        let payload = Data(repeating: 0xAB, count: 3 * 1024 * 1024)
        let encoded = try IPCFraming.encode(.video, payload: payload)
        var decoder = FrameDecoder()
        var frames: [IPCFrame] = []
        var offset = 0
        while offset < encoded.count {
            let end = min(offset + 65_536, encoded.count)
            frames += try decoder.append(encoded.subdata(in: offset..<end))
            offset = end
        }
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0].payload.count, payload.count)
    }

    func testOversizeLengthRejected() {
        var decoder = FrameDecoder()
        let tooBig = UInt32(IPCFraming.maxFrameLength + 1)
        var header = Data()
        BigEndian.append(tooBig, to: &header)
        header.append(0x82)
        XCTAssertThrowsError(try decoder.append(header)) { error in
            XCTAssertEqual(error as? FramingError, .invalidLength(Int(tooBig)))
        }
    }

    func testMaximumLengthAccepted() throws {
        // A header announcing exactly 16 MiB is valid (the frame is just incomplete).
        var decoder = FrameDecoder()
        var header = Data()
        BigEndian.append(UInt32(IPCFraming.maxFrameLength), to: &header)
        XCTAssertEqual(try decoder.append(header), [])
    }

    func testZeroLengthRejected() {
        var decoder = FrameDecoder()
        XCTAssertThrowsError(try decoder.append(Data([0, 0, 0, 0])))
    }

    func testEncodeRejectsOversizePayload() {
        let payload = Data(count: IPCFraming.maxFrameLength)  // + type byte = max + 1
        XCTAssertThrowsError(try IPCFraming.encode(.video, payload: payload))
    }

    func testVideoPayloadLayout() {
        let au = Data([0, 0, 0, 1, 0x65, 0x88])
        let p = MediaPayload.video(codec: .h265, keyframe: true, ptsMicros: 0x0102_0304_0506_0708, accessUnit: au)
        XCTAssertEqual([UInt8](p.prefix(10)), [2, 1, 1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertEqual(p.suffix(from: 10), au)
        let decoded = MediaPayload.decodeVideo(p)
        XCTAssertEqual(decoded?.codec, 2)
        XCTAssertEqual(decoded?.keyframe, true)
        XCTAssertEqual(decoded?.ptsMicros, 0x0102_0304_0506_0708)
        XCTAssertEqual(decoded?.accessUnit, au)

        let delta = MediaPayload.video(codec: .h264, keyframe: false, ptsMicros: 1, accessUnit: Data())
        XCTAssertEqual([UInt8](delta), [1, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    func testAudioPayloadLayout() {
        let p = MediaPayload.audio(ptsMicros: 20_000, packet: Data([0xFC, 0xFF]))
        XCTAssertEqual([UInt8](p), [0, 0, 0, 0, 0, 0, 0x4E, 0x20, 0xFC, 0xFF])
    }

    func testTypeValuesMatchProtocol() {
        XCTAssertEqual(IPCType.config.rawValue, 0x01)
        XCTAssertEqual(IPCType.signResult.rawValue, 0x02)
        XCTAssertEqual(IPCType.video.rawValue, 0x03)
        XCTAssertEqual(IPCType.audio.rawValue, 0x04)
        XCTAssertEqual(IPCType.command.rawValue, 0x05)
        XCTAssertEqual(IPCType.signRequest.rawValue, 0x81)
        XCTAssertEqual(IPCType.state.rawValue, 0x82)
        XCTAssertEqual(IPCType.input.rawValue, 0x83)
        XCTAssertEqual(IPCType.encoder.rawValue, 0x84)
        XCTAssertEqual(IPCType.audioControl.rawValue, 0x85)
        XCTAssertEqual(IPCType.clipboardSet.rawValue, 0x86)
        XCTAssertEqual(IPCType.event.rawValue, 0x87)
        XCTAssertEqual(IPCType.log.rawValue, 0x88)
    }
}
