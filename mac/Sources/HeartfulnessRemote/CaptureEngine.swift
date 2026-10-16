import CoreGraphics
import CoreMedia
import CoreVideo
import Foundation
import HRCore
import ScreenCaptureKit

/// ScreenCaptureKit capture of one display (+ system audio), feeding VideoEncoder /
/// AudioEncoder and the agent. Driven by ENCODER / AUDIO_CTL frames from the agent.
/// All state is confined to `queue` (video) and `audioQueue` (audio).
final class CaptureEngine: NSObject, SCStreamOutput, SCStreamDelegate, @unchecked Sendable {
    private struct StartParams {
        var codec: VideoCodecID
        var fps: Int
        var kbps: Int
        var display: CGDirectDisplayID?
        var profile: H264Profile
    }

    /// Display the stream is (now) showing — called on the capture queue.
    var onActiveDisplayChanged: (@Sendable (CGDirectDisplayID) -> Void)?
    /// User-facing capture problem (nil = cleared) — called on the capture queue.
    var onProblem: (@Sendable (String?) -> Void)?

    private let agent: AgentProcess
    private let queue = DispatchQueue(label: "org.heartfulness.remote.capture", qos: .userInteractive)
    private let audioQueue = DispatchQueue(label: "org.heartfulness.remote.capture.audio", qos: .userInteractive)

    // Video state (queue only)
    private var hevcAvailable = false
    private var audioAvailable = false
    private var params: StartParams?
    private var activeStream: SCStream?
    private var activeConfig: SCStreamConfiguration?
    private var encoder: VideoEncoder?
    private var generation = 0
    private var lastPixelBuffer: CVPixelBuffer?
    private var lastEncodeTime: Double = 0
    private var lastPtsMicros: UInt64 = 0
    private var idleTimer: DispatchSourceTimer?
    private var restartAttempts = 0

    // Shared between queue and VideoToolbox callback threads
    private let flagLock = NSLock()
    private var keyframeRequested = false

    // Audio state (audioQueue only, except the lock-protected flag)
    private let audioLock = NSLock()
    private var audioEnabledFlag = false
    private var audioEncoder: AudioEncoder?

    init(agent: AgentProcess) {
        self.agent = agent
        super.init()
    }

    func setCapabilities(hevc: Bool, audio: Bool) {
        queue.async {
            self.hevcAvailable = hevc
            self.audioAvailable = audio
        }
        guard audio else { return }
        audioQueue.async {
            let agent = self.agent
            self.audioEncoder = AudioEncoder { packet, pts in
                agent.sendAudio(ptsMicros: pts, packet: packet)
            }
        }
    }

    // MARK: Commands from the agent (any thread)

    func handle(_ command: EncoderCommand) {
        queue.async {
            switch command.action {
            case let .start(codec, fps, kbps, display, profile):
                self.start(StartParams(codec: codec, fps: fps, kbps: kbps, display: display, profile: profile))
            case .stop:
                self.params = nil
                self.stopStream()
            case .keyframe:
                self.requestKeyframe()
            case .bitrate(let kbps):
                self.params?.kbps = kbps
                self.encoder?.applyBitrate(kbps: kbps)
                // The agent drops to 30 fps on slow connections (and back to 60).
                if let fps = command.fps, fps > 0 {
                    self.applyFrameRate(min(max(fps, 1), 120))
                }
            case .display(let id):
                guard var p = self.params else { return }
                p.display = id
                self.start(p)
            case .unknown(let name):
                Log.capture.notice("Ignoring unknown encoder command \(name, privacy: .public)")
            }
        }
    }

    func setAudioEnabled(_ enabled: Bool) {
        audioLock.lock()
        audioEnabledFlag = enabled
        audioLock.unlock()
        audioQueue.async {
            self.audioEncoder?.reset()
        }
    }

    /// Stop everything immediately (kill switch, helper exit, quit).
    func stopAll() {
        setAudioEnabled(false)
        queue.async {
            self.params = nil
            self.stopStream()
        }
    }

    // MARK: Stream lifecycle (queue)

    private func start(_ p: StartParams) {
        stopStream()
        params = p
        generation += 1
        let myGeneration = generation
        SCShareableContent.getExcludingDesktopWindows(false, onScreenWindowsOnly: true) { [weak self] content, error in
            guard let self else { return }
            self.queue.async {
                guard myGeneration == self.generation else { return }
                guard let content else {
                    Log.capture.error("Screen content unavailable: \(error?.localizedDescription ?? "unknown", privacy: .public)")
                    self.onProblem?("Screen Recording permission is missing. Open Heartfulness Remote → Status to fix it.")
                    return
                }
                self.configure(content: content, params: p, generation: myGeneration)
            }
        }
    }

    private func configure(content: SCShareableContent, params p: StartParams, generation myGeneration: Int) {
        let mainID = CGMainDisplayID()
        let display = content.displays.first(where: { $0.displayID == p.display })
            ?? content.displays.first(where: { $0.displayID == mainID })
            ?? content.displays.first
        guard let display else {
            onProblem?("No display found to share.")
            return
        }

        // Exclude this app (its "being controlled" banner and windows) from the stream.
        let pid = ProcessInfo.processInfo.processIdentifier
        let ownApps = content.applications.filter { $0.processID == pid }
        let filter = SCContentFilter(display: display, excludingApplications: ownApps, exceptingWindows: [])

        var pixelWidth = display.width
        var pixelHeight = display.height
        if let mode = CGDisplayCopyDisplayMode(display.displayID) {
            pixelWidth = mode.pixelWidth
            pixelHeight = mode.pixelHeight
        }
        let size = CaptureSizing.outputSize(pixelWidth: pixelWidth, pixelHeight: pixelHeight)

        let config = SCStreamConfiguration()
        config.width = size.width
        config.height = size.height
        config.minimumFrameInterval = CMTime(value: 1, timescale: CMTimeScale(max(1, p.fps)))
        config.pixelFormat = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
        config.showsCursor = true
        config.queueDepth = 5
        if audioAvailable {
            config.capturesAudio = true
            config.excludesCurrentProcessAudio = true
            config.sampleRate = 48_000
            config.channelCount = 2
        }

        var codec = p.codec
        if codec == .h265 && !hevcAvailable {
            Log.capture.notice("HEVC requested but not available; using H.264")
            codec = .h264
        }
        let agent = self.agent
        let streamCodec = codec
        let output: VideoEncoder.Output = { [weak self] data, keyframe, pts in
            let sent = agent.sendVideo(codec: streamCodec, keyframe: keyframe, ptsMicros: pts, accessUnit: data)
            if !sent { self?.markKeyframeNeeded() }
        }
        let videoEncoder: VideoEncoder
        do {
            videoEncoder = try VideoEncoder(width: size.width, height: size.height, codec: streamCodec,
                                            profile: p.profile, fps: p.fps, kbps: p.kbps, output: output)
        } catch {
            Log.capture.error("Could not create the video encoder: \(String(describing: error), privacy: .public)")
            onProblem?("The video encoder could not start.")
            return
        }

        let newStream = SCStream(filter: filter, configuration: config, delegate: self)
        do {
            try newStream.addStreamOutput(self, type: .screen, sampleHandlerQueue: queue)
            if audioAvailable {
                try newStream.addStreamOutput(self, type: .audio, sampleHandlerQueue: audioQueue)
            }
        } catch {
            Log.capture.error("Could not attach stream outputs: \(error.localizedDescription, privacy: .public)")
            videoEncoder.invalidate()
            onProblem?("Screen capture could not start.")
            return
        }

        activeStream = newStream
        activeConfig = config
        encoder = videoEncoder
        lastPixelBuffer = nil
        lastEncodeTime = 0
        markKeyframeNeeded()
        startIdleTimer()

        newStream.startCapture { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard myGeneration == self.generation else { return }
                if let error {
                    Log.capture.error("startCapture failed: \(error.localizedDescription, privacy: .public)")
                    self.onProblem?("Screen capture could not start. Check Screen Recording permission.")
                    self.stopStream()
                } else {
                    self.restartAttempts = 0
                    self.onProblem?(nil)
                }
            }
        }
        onActiveDisplayChanged?(display.displayID)
        Log.capture.notice("Capturing display \(display.displayID, privacy: .public) at \(size.width, privacy: .public)x\(size.height, privacy: .public)")
    }

    private func stopStream() {
        generation += 1
        idleTimer?.cancel()
        idleTimer = nil
        if let current = activeStream {
            current.stopCapture { _ in }
        }
        activeStream = nil
        activeConfig = nil
        encoder?.invalidate()
        encoder = nil
        lastPixelBuffer = nil
    }

    /// Changes the capture and encoder frame rate of the running stream in place.
    private func applyFrameRate(_ fps: Int) {
        guard var p = params, p.fps != fps else { return }
        p.fps = fps
        params = p
        encoder?.applyFrameRate(fps)
        guard let stream = activeStream, let config = activeConfig else { return }
        config.minimumFrameInterval = CMTime(value: 1, timescale: CMTimeScale(fps))
        stream.updateConfiguration(config) { error in
            if let error {
                Log.capture.error("Frame rate change failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        Log.capture.notice("Frame rate now \(fps, privacy: .public) fps")
    }

    private func startIdleTimer() {
        idleTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 0.25, repeating: 0.25)
        timer.setEventHandler { [weak self] in
            self?.idleTick()
        }
        timer.resume()
        idleTimer = timer
    }

    /// When the screen is static, ScreenCaptureKit sends nothing; re-send the last frame
    /// at 1 fps so the stream (and the client's decoder) stays alive.
    private func idleTick() {
        guard encoder != nil, let buffer = lastPixelBuffer else { return }
        let now = CaptureEngine.hostSeconds()
        if now - lastEncodeTime >= 1.0 {
            encodeFrame(buffer, hostSeconds: now)
        }
    }

    private func requestKeyframe() {
        markKeyframeNeeded()
        if let buffer = lastPixelBuffer {
            encodeFrame(buffer, hostSeconds: CaptureEngine.hostSeconds())
        }
    }

    private func markKeyframeNeeded() {
        flagLock.lock()
        keyframeRequested = true
        flagLock.unlock()
    }

    private func takeKeyframeRequest() -> Bool {
        flagLock.lock()
        defer { flagLock.unlock() }
        let value = keyframeRequested
        keyframeRequested = false
        return value
    }

    private func encodeFrame(_ buffer: CVPixelBuffer, hostSeconds: Double) {
        guard let encoder else { return }
        var micros = hostSeconds.isFinite && hostSeconds > 0 ? UInt64(hostSeconds * 1_000_000) : lastPtsMicros + 1
        if micros <= lastPtsMicros { micros = lastPtsMicros + 1 }
        lastPtsMicros = micros
        lastEncodeTime = CaptureEngine.hostSeconds()
        encoder.encode(pixelBuffer: buffer, ptsMicros: micros, forceKeyframe: takeKeyframeRequest())
    }

    static func hostSeconds() -> Double {
        CMTimeGetSeconds(CMClockGetTime(CMClockGetHostTimeClock()))
    }

    // MARK: SCStreamOutput

    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of type: SCStreamOutputType) {
        switch type {
        case .screen:
            handleVideo(sampleBuffer, from: stream)
        case .audio:
            handleAudio(sampleBuffer)
        default:
            break
        }
    }

    private func handleVideo(_ sampleBuffer: CMSampleBuffer, from source: SCStream) {
        guard source === activeStream, sampleBuffer.isValid else { return }
        guard let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]],
              let info = attachments.first,
              let rawStatus = info[SCStreamFrameInfo.status] as? Int,
              let status = SCFrameStatus(rawValue: rawStatus),
              status == .complete,
              let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else {
            return
        }
        lastPixelBuffer = pixelBuffer
        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        let seconds = pts.isValid ? CMTimeGetSeconds(pts) : CaptureEngine.hostSeconds()
        encodeFrame(pixelBuffer, hostSeconds: seconds)
    }

    private func handleAudio(_ sampleBuffer: CMSampleBuffer) {
        audioLock.lock()
        let enabled = audioEnabledFlag
        audioLock.unlock()
        guard enabled, sampleBuffer.isValid else { return }
        audioEncoder?.encode(sampleBuffer: sampleBuffer)
    }

    // MARK: SCStreamDelegate

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        queue.async {
            guard stream === self.activeStream else { return }
            Log.capture.error("Stream stopped: \(error.localizedDescription, privacy: .public)")
            self.stopStream()
            // Try to recover (e.g. display reconfigured) a few times.
            guard let p = self.params, self.restartAttempts < 3 else {
                self.onProblem?("Screen capture stopped.")
                return
            }
            self.restartAttempts += 1
            self.queue.asyncAfter(deadline: .now() + 1) {
                guard self.params != nil, self.activeStream == nil else { return }
                self.start(p)
            }
        }
    }
}
