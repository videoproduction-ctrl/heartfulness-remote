import CoreMedia
import CoreVideo
import Foundation
import HRCore
import VideoToolbox

/// Hardware H.264 / HEVC encoder tuned for interactive remote control: real-time,
/// low-latency rate control, no B-frames, keyframes on demand.
/// All methods except the output callback are called on the capture queue.
final class VideoEncoder: @unchecked Sendable {
    enum EncoderError: Error {
        case sessionCreate(OSStatus)
    }

    /// (Annex-B access unit, keyframe, pts in µs) — called on a VideoToolbox thread.
    typealias Output = @Sendable (Data, Bool, UInt64) -> Void

    let codec: VideoCodecID
    let width: Int
    let height: Int
    private var session: VTCompressionSession?
    private let output: Output

    init(width: Int, height: Int, codec: VideoCodecID, profile: H264Profile, fps: Int, kbps: Int, output: @escaping Output) throws {
        self.codec = codec
        self.width = width
        self.height = height
        self.output = output

        var created = VideoEncoder.makeSession(width: width, height: height, codec: codec, lowLatency: true, requireHardware: false)
        if created.session == nil {
            Log.capture.notice("Low-latency encoder unavailable (\(created.status, privacy: .public)); using the standard encoder")
            created = VideoEncoder.makeSession(width: width, height: height, codec: codec, lowLatency: false, requireHardware: false)
        }
        guard let session = created.session else { throw EncoderError.sessionCreate(created.status) }
        self.session = session

        set(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
        set(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse)
        let profileLevel: CFString
        switch codec {
        case .h264:
            profileLevel = profile == .baseline ? kVTProfileLevel_H264_ConstrainedBaseline_AutoLevel : kVTProfileLevel_H264_High_AutoLevel
        case .h265:
            profileLevel = kVTProfileLevel_HEVC_Main_AutoLevel
        }
        set(session, kVTCompressionPropertyKey_ProfileLevel, profileLevel)
        set(session, kVTCompressionPropertyKey_ExpectedFrameRate, NSNumber(value: fps))
        set(session, kVTCompressionPropertyKey_MaxKeyFrameInterval, NSNumber(value: 600))
        set(session, kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality, kCFBooleanTrue)
        applyBitrate(kbps: kbps)
        VTCompressionSessionPrepareToEncodeFrames(session)
        Log.capture.notice("Encoder ready: \(codec == .h264 ? "H.264" : "HEVC", privacy: .public) \(width, privacy: .public)x\(height, privacy: .public) @\(fps, privacy: .public)fps \(kbps, privacy: .public)kbps")
    }

    deinit {
        invalidate()
    }

    func invalidate() {
        guard let session else { return }
        self.session = nil
        VTCompressionSessionInvalidate(session)
    }

    func encode(pixelBuffer: CVPixelBuffer, ptsMicros: UInt64, forceKeyframe: Bool) {
        guard let session else { return }
        let pts = CMTime(value: CMTimeValue(ptsMicros), timescale: 1_000_000)
        var properties: CFDictionary?
        if forceKeyframe {
            properties = [kVTEncodeFrameOptionKey_ForceKeyFrame as String: true] as CFDictionary
        }
        let codec = self.codec
        let output = self.output
        let status = VTCompressionSessionEncodeFrame(
            session,
            imageBuffer: pixelBuffer,
            presentationTimeStamp: pts,
            duration: CMTime.invalid,
            frameProperties: properties,
            infoFlagsOut: nil
        ) { encodeStatus, _, sampleBuffer in
            guard encodeStatus == 0, let sampleBuffer else { return }
            guard let unit = VideoEncoder.annexB(from: sampleBuffer, codec: codec) else { return }
            output(unit.data, unit.keyframe, ptsMicros)
        }
        if status != 0 {
            Log.capture.error("VTCompressionSessionEncodeFrame failed: \(status, privacy: .public)")
        }
    }

    func applyBitrate(kbps: Int) {
        guard let session else { return }
        let bitsPerSecond = max(250, kbps) * 1000
        set(session, kVTCompressionPropertyKey_AverageBitRate, NSNumber(value: bitsPerSecond))
        // Cap short bursts at 1.5× the average over one second (not supported by every
        // encoder mode; failures are harmless).
        let bytesPerSecond = Double(bitsPerSecond) * 1.5 / 8.0
        let limits = [NSNumber(value: bytesPerSecond), NSNumber(value: 1.0)] as CFArray
        set(session, kVTCompressionPropertyKey_DataRateLimits, limits)
    }

    func applyFrameRate(_ fps: Int) {
        guard let session else { return }
        set(session, kVTCompressionPropertyKey_ExpectedFrameRate, NSNumber(value: max(1, fps)))
    }

    private func set(_ session: VTCompressionSession, _ key: CFString, _ value: CFTypeRef?) {
        let status = VTSessionSetProperty(session, key: key, value: value)
        if status != 0 {
            Log.capture.debug("VTSessionSetProperty \(key as String, privacy: .public) → \(status, privacy: .public)")
        }
    }

    // MARK: Session creation

    private static func makeSession(width: Int, height: Int, codec: VideoCodecID, lowLatency: Bool, requireHardware: Bool) -> (session: VTCompressionSession?, status: OSStatus) {
        var specification: [String: Any] = [:]
        if lowLatency {
            specification[kVTVideoEncoderSpecification_EnableLowLatencyRateControl as String] = true
        }
        if requireHardware {
            specification[kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder as String] = true
        }
        let codecType: CMVideoCodecType = codec == .h264 ? kCMVideoCodecType_H264 : kCMVideoCodecType_HEVC
        var session: VTCompressionSession?
        let status = VTCompressionSessionCreate(
            allocator: kCFAllocatorDefault,
            width: Int32(width),
            height: Int32(height),
            codecType: codecType,
            encoderSpecification: specification as CFDictionary,
            imageBufferAttributes: nil,
            compressedDataAllocator: nil,
            outputCallback: nil,
            refcon: nil,
            compressionSessionOut: &session
        )
        return (status == 0 ? session : nil, status)
    }

    /// Whether this Mac can encode HEVC in hardware (checked once at launch).
    static func isHEVCEncodeAvailable() -> Bool {
        let created = makeSession(width: 1280, height: 720, codec: .h265, lowLatency: false, requireHardware: true)
        guard let session = created.session else { return false }
        VTCompressionSessionInvalidate(session)
        return true
    }

    // MARK: Output conversion

    /// Converts an encoded sample buffer to an Annex-B access unit. Keyframes are prefixed
    /// with the parameter sets (SPS/PPS, plus VPS for HEVC) from the format description.
    static func annexB(from sampleBuffer: CMSampleBuffer, codec: VideoCodecID) -> (data: Data, keyframe: Bool)? {
        guard let block = CMSampleBufferGetDataBuffer(sampleBuffer) else { return nil }
        let length = CMBlockBufferGetDataLength(block)
        guard length > 0 else { return nil }
        var raw = Data(count: length)
        let copyStatus: OSStatus = raw.withUnsafeMutableBytes { buffer -> OSStatus in
            guard let base = buffer.baseAddress else { return -1 }
            return CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: length, destination: base)
        }
        guard copyStatus == 0 else { return nil }

        let keyframe = isKeyframe(sampleBuffer)
        var parameterSets: [Data] = []
        var lengthSize = 4
        if let format = CMSampleBufferGetFormatDescription(sampleBuffer) {
            let info = parameterSetInfo(format, codec: codec)
            if info.lengthSize >= 1 && info.lengthSize <= 4 { lengthSize = info.lengthSize }
            if keyframe { parameterSets = info.sets }
        }
        guard let unit = try? AnnexB.accessUnit(parameterSets: parameterSets, lengthPrefixed: raw, lengthSize: lengthSize) else {
            return nil
        }
        return (unit, keyframe)
    }

    static func isKeyframe(_ sampleBuffer: CMSampleBuffer) -> Bool {
        guard let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false) as? [NSDictionary],
              let first = attachments.first else {
            return true
        }
        if let notSync = first[kCMSampleAttachmentKey_NotSync] as? Bool {
            return !notSync
        }
        return true
    }

    private static func parameterSetInfo(_ format: CMFormatDescription, codec: VideoCodecID) -> (sets: [Data], lengthSize: Int) {
        var count = 0
        var headerLength: Int32 = 4
        let probe: OSStatus
        switch codec {
        case .h264:
            probe = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                format, parameterSetIndex: 0, parameterSetPointerOut: nil, parameterSetSizeOut: nil,
                parameterSetCountOut: &count, nalUnitHeaderLengthOut: &headerLength)
        case .h265:
            probe = CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
                format, parameterSetIndex: 0, parameterSetPointerOut: nil, parameterSetSizeOut: nil,
                parameterSetCountOut: &count, nalUnitHeaderLengthOut: &headerLength)
        }
        guard probe == 0 else { return ([], 4) }

        var sets: [Data] = []
        for index in 0..<count {
            var pointer: UnsafePointer<UInt8>?
            var size = 0
            let status: OSStatus
            switch codec {
            case .h264:
                status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                    format, parameterSetIndex: index, parameterSetPointerOut: &pointer, parameterSetSizeOut: &size,
                    parameterSetCountOut: nil, nalUnitHeaderLengthOut: nil)
            case .h265:
                status = CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
                    format, parameterSetIndex: index, parameterSetPointerOut: &pointer, parameterSetSizeOut: &size,
                    parameterSetCountOut: nil, nalUnitHeaderLengthOut: nil)
            }
            if status == 0, let pointer, size > 0 {
                sets.append(Data(bytes: pointer, count: size))
            }
        }
        return (sets, Int(headerLength))
    }
}
