import AVFoundation
import CoreMedia
import Foundation

/// System audio (ScreenCaptureKit PCM, normally Float32 48 kHz stereo) → Opus packets
/// of 20 ms (960 frames) using AVAudioConverter's compressed-buffer API.
/// Not thread-safe: use from the audio capture queue only.
final class AudioEncoder: @unchecked Sendable {
    /// (Opus packet, pts in µs)
    typealias Output = @Sendable (Data, UInt64) -> Void

    static let sampleRate: Double = 48_000
    static let framesPerPacket: UInt32 = 960
    static let packetDurationMicros: UInt64 = 20_000

    private let output: Output
    private let outputFormat: AVAudioFormat
    private var converter: AVAudioConverter?
    private var inputFormat: AVAudioFormat?
    private var inputQueue: [AVAudioPCMBuffer] = []
    private var anchorMicros: Int64?
    private var framesIn: Int64 = 0
    private var packetsOut: UInt64 = 0

    init?(output: @escaping Output) {
        guard let format = AudioEncoder.makeOpusFormat() else { return nil }
        self.outputFormat = format
        self.output = output
    }

    static func makeOpusFormat() -> AVAudioFormat? {
        var description = AudioStreamBasicDescription(
            mSampleRate: sampleRate,
            mFormatID: kAudioFormatOpus,
            mFormatFlags: 0,
            mBytesPerPacket: 0,
            mFramesPerPacket: framesPerPacket,
            mBytesPerFrame: 0,
            mChannelsPerFrame: 2,
            mBitsPerChannel: 0,
            mReserved: 0
        )
        return AVAudioFormat(streamDescription: &description)
    }

    /// Checked once at launch; if false, CONFIG reports audioAvailable=false.
    static func isAvailable() -> Bool {
        guard let opus = makeOpusFormat(),
              let pcm = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 2) else {
            return false
        }
        return AVAudioConverter(from: pcm, to: opus) != nil
    }

    /// Forget timing and buffered audio (on AUDIO_CTL start/stop).
    func reset() {
        inputQueue.removeAll()
        converter?.reset()
        anchorMicros = nil
        framesIn = 0
        packetsOut = 0
    }

    func encode(sampleBuffer: CMSampleBuffer) {
        guard let formatDescription = CMSampleBufferGetFormatDescription(sampleBuffer),
              let asbd = CMAudioFormatDescriptionGetStreamBasicDescription(formatDescription) else {
            return
        }
        let frameCount = CMSampleBufferGetNumSamples(sampleBuffer)
        guard frameCount > 0 else { return }

        if converter == nil || !sameFormat(asbd.pointee) {
            guard rebuildConverter(asbd) else { return }
        }
        guard let converter, let inputFormat else { return }

        guard let pcm = AVAudioPCMBuffer(pcmFormat: inputFormat, frameCapacity: AVAudioFrameCount(frameCount)) else { return }
        pcm.frameLength = AVAudioFrameCount(frameCount)
        let copyStatus = CMSampleBufferCopyPCMDataIntoAudioBufferList(
            sampleBuffer, at: 0, frameCount: Int32(frameCount), into: pcm.mutableAudioBufferList)
        guard copyStatus == 0 else { return }

        updateTiming(sampleBuffer, inputRate: inputFormat.sampleRate)
        framesIn += Int64(frameCount)
        inputQueue.append(pcm)
        drain(converter)
    }

    // MARK: Private

    private func sameFormat(_ asbd: AudioStreamBasicDescription) -> Bool {
        guard let current = inputFormat?.streamDescription.pointee else { return false }
        return current.mSampleRate == asbd.mSampleRate
            && current.mChannelsPerFrame == asbd.mChannelsPerFrame
            && current.mFormatID == asbd.mFormatID
            && current.mFormatFlags == asbd.mFormatFlags
            && current.mBitsPerChannel == asbd.mBitsPerChannel
    }

    private func rebuildConverter(_ asbd: UnsafePointer<AudioStreamBasicDescription>) -> Bool {
        guard let format = AVAudioFormat(streamDescription: asbd),
              let newConverter = AVAudioConverter(from: format, to: outputFormat) else {
            Log.capture.error("Could not create the Opus audio converter")
            converter = nil
            inputFormat = nil
            return false
        }
        if let rates = newConverter.applicableEncodeBitRates?.map({ $0.intValue }),
           let best = rates.filter({ $0 <= 128_000 }).max() {
            newConverter.bitRate = best
        }
        converter = newConverter
        inputFormat = format
        inputQueue.removeAll()
        anchorMicros = nil
        framesIn = 0
        packetsOut = 0
        return true
    }

    /// Keeps packet timestamps on the capture clock; re-anchors after gaps or drift > 100 ms.
    private func updateTiming(_ sampleBuffer: CMSampleBuffer, inputRate: Double) {
        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        let seconds = pts.isValid ? CMTimeGetSeconds(pts) : CMTimeGetSeconds(CMClockGetTime(CMClockGetHostTimeClock()))
        guard seconds.isFinite, seconds >= 0 else { return }
        let actual = Int64(seconds * 1_000_000)
        let rate = inputRate > 0 ? inputRate : AudioEncoder.sampleRate
        let offset = Int64(Double(framesIn) * 1_000_000 / rate)
        guard let anchor = anchorMicros else {
            anchorMicros = actual - offset
            return
        }
        if abs((anchor + offset) - actual) > 100_000 {
            anchorMicros = actual - offset
        }
    }

    private func drain(_ converter: AVAudioConverter) {
        let maxPacketSize = max(converter.maximumOutputPacketSize, 1500)
        for _ in 0..<64 {
            let buffer = AVAudioCompressedBuffer(format: outputFormat, packetCapacity: 8, maximumPacketSize: maxPacketSize)
            var error: NSError?
            let status = converter.convert(to: buffer, error: &error) { _, inputStatus in
                if self.inputQueue.isEmpty {
                    inputStatus.pointee = .noDataNow
                    return nil
                }
                inputStatus.pointee = .haveData
                return self.inputQueue.removeFirst()
            }
            emitPackets(buffer)
            if status == .error {
                Log.capture.error("Opus encode error: \(error?.localizedDescription ?? "unknown", privacy: .public)")
                inputQueue.removeAll()
                return
            }
            if status != .haveData || buffer.packetCount == 0 { return }
        }
    }

    private func emitPackets(_ buffer: AVAudioCompressedBuffer) {
        let count = Int(buffer.packetCount)
        guard count > 0, let descriptions = buffer.packetDescriptions else { return }
        let base = anchorMicros ?? 0
        for index in 0..<count {
            let description = descriptions[index]
            let size = Int(description.mDataByteSize)
            guard size > 0 else { continue }
            let start = buffer.data.advanced(by: Int(description.mStartOffset))
            let packet = Data(bytes: start, count: size)
            let ptsSigned = base + Int64(packetsOut) * Int64(AudioEncoder.packetDurationMicros)
            packetsOut += 1
            output(packet, UInt64(max(0, ptsSigned)))
        }
    }
}
