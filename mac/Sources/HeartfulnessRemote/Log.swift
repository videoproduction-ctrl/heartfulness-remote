import Foundation
import os

/// Unified logging. Never log key material, the storage key, setup URLs or clipboard text.
enum Log {
    static let subsystem = "org.heartfulness.remote.host"
    static let app = Logger(subsystem: subsystem, category: "app")
    static let agent = Logger(subsystem: subsystem, category: "agent")
    static let keys = Logger(subsystem: subsystem, category: "keys")
    static let capture = Logger(subsystem: subsystem, category: "capture")
    static let input = Logger(subsystem: subsystem, category: "input")
}

/// Runs a closure on the main actor, always asynchronously and in FIFO order
/// (unlike `Task { @MainActor in }`, which does not guarantee ordering).
func onMain(_ body: @escaping @MainActor () -> Void) {
    DispatchQueue.main.async {
        MainActor.assumeIsolated {
            body()
        }
    }
}
