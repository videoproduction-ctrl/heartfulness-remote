import Foundation
import HRCore
import os

/// Launches the bundled `hr-agent` helper and exchanges IPC frames with it over
/// stdin/stdout pipes (PROTOCOL.md §9). Restart policy lives in AppModel.
final class AgentProcess: @unchecked Sendable {
    enum LaunchError: Error {
        case helperMissing
    }

    /// Called on the stdout reader thread for every decoded frame.
    var onFrame: (@Sendable (IPCFrame) -> Void)?
    /// Called (on an arbitrary thread) when the helper exits unexpectedly. Argument: exit status.
    var onExit: (@Sendable (Int32) -> Void)?

    /// Video frames are dropped (and a keyframe requested) once this many bytes are queued.
    private let maxQueuedBytes = 8 * 1024 * 1024

    private let lock = NSLock()
    private let writeQueue = DispatchQueue(label: "org.heartfulness.remote.agent.write", qos: .userInteractive)
    private var process: Process?
    private var stdinHandle: FileHandle?
    private var generation = 0
    private var queuedBytes = 0

    var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return process?.isRunning ?? false
    }

    static var helperURL: URL? {
        Bundle.main.url(forAuxiliaryExecutable: "hr-agent")
    }

    /// Starts the helper and sends CONFIG as the very first frame.
    func start(config: AgentConfig) throws {
        stop()
        guard let url = AgentProcess.helperURL else { throw LaunchError.helperMissing }

        let process = Process()
        process.executableURL = url
        process.arguments = []
        // Minimal, predictable environment; nothing secret is passed this way.
        var env: [String: String] = [
            "HOME": NSHomeDirectory(),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": NSTemporaryDirectory(),
            "LANG": "en_US.UTF-8",
        ]
        if let user = ProcessInfo.processInfo.environment["USER"] { env["USER"] = user }
        process.environment = env

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        lock.lock()
        generation += 1
        let myGeneration = generation
        lock.unlock()

        process.terminationHandler = { [weak self] finished in
            self?.didTerminate(status: finished.terminationStatus, generation: myGeneration)
        }

        try process.run()
        Log.agent.notice("hr-agent started (pid \(process.processIdentifier, privacy: .public))")

        lock.lock()
        self.process = process
        self.stdinHandle = stdinPipe.fileHandleForWriting
        self.queuedBytes = 0
        lock.unlock()

        startStdoutReader(stdoutPipe.fileHandleForReading, generation: myGeneration)
        startStderrReader(stderrPipe.fileHandleForReading)

        sendJSON(.config, config)
    }

    /// Stops the helper: closes stdin (the agent exits on EOF), then terminates it if needed.
    func stop() {
        lock.lock()
        let process = self.process
        let handle = stdinHandle
        self.process = nil
        stdinHandle = nil
        generation += 1   // the termination handler of the old process is now ignored
        queuedBytes = 0
        lock.unlock()

        guard let process else { return }
        writeQueue.async {
            try? handle?.close()
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
            if process.isRunning {
                Log.agent.notice("hr-agent did not exit after stdin closed; terminating")
                process.terminate()
            }
        }
    }

    // MARK: Sending

    /// Queues a frame for writing. Droppable frames are refused when the pipe is backed up.
    /// Returns false if the frame was not queued.
    @discardableResult
    func send(_ type: IPCType, payload: Data, droppable: Bool = false) -> Bool {
        let frame: Data
        do {
            frame = try IPCFraming.encode(type, payload: payload)
        } catch {
            Log.agent.error("Frame too large to send (\(payload.count, privacy: .public) bytes)")
            return false
        }
        lock.lock()
        guard let handle = stdinHandle else {
            lock.unlock()
            return false
        }
        if droppable && queuedBytes + frame.count > maxQueuedBytes {
            lock.unlock()
            return false
        }
        queuedBytes += frame.count
        let myGeneration = generation
        lock.unlock()

        writeQueue.async { [weak self] in
            do {
                try handle.write(contentsOf: frame)
            } catch {
                // Broken pipe: the helper died. The termination handler takes care of it.
            }
            guard let self else { return }
            self.lock.lock()
            if self.generation == myGeneration { self.queuedBytes -= frame.count }
            self.lock.unlock()
        }
        return true
    }

    @discardableResult
    func sendJSON<T: Encodable>(_ type: IPCType, _ value: T) -> Bool {
        do {
            return send(type, payload: try HRJSON.encode(value))
        } catch {
            Log.agent.error("Could not encode \(String(describing: type), privacy: .public) frame")
            return false
        }
    }

    @discardableResult
    func send(command: AgentCommand) -> Bool {
        sendJSON(.command, command)
    }

    /// VIDEO frame; delta frames may be dropped under back-pressure (returns false).
    func sendVideo(codec: VideoCodecID, keyframe: Bool, ptsMicros: UInt64, accessUnit: Data) -> Bool {
        let payload = MediaPayload.video(codec: codec, keyframe: keyframe, ptsMicros: ptsMicros, accessUnit: accessUnit)
        return send(.video, payload: payload, droppable: !keyframe)
    }

    func sendAudio(ptsMicros: UInt64, packet: Data) {
        send(.audio, payload: MediaPayload.audio(ptsMicros: ptsMicros, packet: packet), droppable: true)
    }

    // MARK: Reading

    private func startStdoutReader(_ handle: FileHandle, generation myGeneration: Int) {
        let thread = Thread { [weak self] in
            var decoder = FrameDecoder()
            while true {
                let chunk: Data?
                do {
                    chunk = try handle.read(upToCount: 64 * 1024)
                } catch {
                    break
                }
                guard let data = chunk, !data.isEmpty else { break }   // EOF
                do {
                    let frames = try decoder.append(data)
                    guard let self else { return }
                    for frame in frames { self.onFrame?(frame) }
                } catch {
                    Log.agent.error("IPC stream out of sync (\(String(describing: error), privacy: .public)); restarting helper")
                    self?.killIfCurrent(generation: myGeneration)
                    return
                }
            }
        }
        thread.name = "hr-agent stdout"
        thread.qualityOfService = .userInteractive
        thread.start()
    }

    private func startStderrReader(_ handle: FileHandle) {
        let thread = Thread {
            var pending = Data()
            while true {
                let chunk: Data?
                do {
                    chunk = try handle.read(upToCount: 16 * 1024)
                } catch {
                    break
                }
                guard let data = chunk, !data.isEmpty else { break }
                pending.append(data)
                while let newline = pending.firstIndex(of: 0x0A) {
                    let lineData = pending[pending.startIndex..<newline]
                    pending.removeSubrange(pending.startIndex...newline)
                    AgentProcess.logStderr(String(decoding: lineData, as: UTF8.self))
                }
                if pending.count > 64 * 1024 {
                    AgentProcess.logStderr(String(decoding: pending, as: UTF8.self))
                    pending.removeAll()
                }
            }
            if !pending.isEmpty { AgentProcess.logStderr(String(decoding: pending, as: UTF8.self)) }
        }
        thread.name = "hr-agent stderr"
        thread.qualityOfService = .utility
        thread.start()
    }

    /// The agent promises never to print secrets; as a second line of defence, lines that
    /// contain long base64-looking tokens are logged as private.
    private static func logStderr(_ rawLine: String) {
        let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !line.isEmpty else { return }
        if looksSecret(line) {
            Log.agent.info("\(line, privacy: .private)")
        } else {
            Log.agent.info("\(line, privacy: .public)")
        }
    }

    static func looksSecret(_ line: String) -> Bool {
        var run = 0
        for scalar in line.unicodeScalars {
            let v = scalar.value
            let isToken = (v >= 0x30 && v <= 0x39) || (v >= 0x41 && v <= 0x5A) || (v >= 0x61 && v <= 0x7A) || v == 0x2D || v == 0x5F
            run = isToken ? run + 1 : 0
            if run >= 40 { return true }
        }
        return line.contains("#setup=")
    }

    // MARK: Termination

    private func killIfCurrent(generation myGeneration: Int) {
        lock.lock()
        let process = myGeneration == generation ? self.process : nil
        lock.unlock()
        process?.terminate()
    }

    private func didTerminate(status: Int32, generation myGeneration: Int) {
        lock.lock()
        let current = myGeneration == generation
        if current {
            process = nil
            stdinHandle = nil
            queuedBytes = 0
        }
        lock.unlock()
        guard current else { return }
        Log.agent.error("hr-agent exited unexpectedly (status \(status, privacy: .public))")
        onExit?(status)
    }
}
