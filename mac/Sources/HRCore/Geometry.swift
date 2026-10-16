import Foundation

/// A display rectangle in global display coordinates (points, origin top-left of the
/// main display, y grows downwards — the same space CGEvent and CGDisplayBounds use).
public struct DisplayRect: Equatable, Sendable {
    public var x: Double
    public var y: Double
    public var width: Double
    public var height: Double

    public init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public struct DisplayPoint: Equatable, Sendable {
    public var x: Double
    public var y: Double

    public init(x: Double, y: Double) {
        self.x = x
        self.y = y
    }
}

/// Maps the client's normalised pointer position (0…1 within the active display)
/// to global display coordinates.
public enum CoordinateMapper {
    /// Clamps to 0…1; NaN/infinity become 0.
    public static func clampUnit(_ value: Double) -> Double {
        guard value.isFinite else { return 0 }
        return min(max(value, 0), 1)
    }

    /// The result always lies inside the display (x ≤ maxX − 1, y ≤ maxY − 1), so a value of
    /// exactly 1.0 never lands on a neighbouring display.
    public static func point(normalizedX: Double, normalizedY: Double, in bounds: DisplayRect) -> DisplayPoint {
        let nx = clampUnit(normalizedX)
        let ny = clampUnit(normalizedY)
        let maxX = bounds.x + max(bounds.width - 1, 0)
        let maxY = bounds.y + max(bounds.height - 1, 0)
        let x = min(bounds.x + nx * bounds.width, maxX)
        let y = min(bounds.y + ny * bounds.height, maxY)
        return DisplayPoint(x: x, y: y)
    }

    /// Inverse mapping (for tests and diagnostics).
    public static func normalized(_ point: DisplayPoint, in bounds: DisplayRect) -> DisplayPoint {
        guard bounds.width > 0, bounds.height > 0 else { return DisplayPoint(x: 0, y: 0) }
        return DisplayPoint(x: clampUnit((point.x - bounds.x) / bounds.width),
                            y: clampUnit((point.y - bounds.y) / bounds.height))
    }
}

/// Output size for screen capture + encoding.
public enum CaptureSizing {
    public static let maxWidth = 3840

    /// Full pixel size, scaled down proportionally if wider than `maxWidth`;
    /// both dimensions rounded down to even numbers (4:2:0 video needs even sizes).
    public static func outputSize(pixelWidth: Int, pixelHeight: Int, maxWidth: Int = CaptureSizing.maxWidth) -> (width: Int, height: Int) {
        let w = max(pixelWidth, 2)
        let h = max(pixelHeight, 2)
        var outW = w
        var outH = h
        if w > maxWidth {
            outW = maxWidth
            outH = Int((Double(h) * Double(maxWidth) / Double(w)).rounded())
        }
        return (even(outW), even(outH))
    }

    private static func even(_ v: Int) -> Int { max(2, v & ~1) }
}

/// Click-count tracking for synthesised mouse events (double/triple click).
public struct ClickCounter: Sendable {
    public var interval: Double
    public var maxDistance: Double

    private var lastButton: Int = -1
    private var lastTime: Double = -Double.greatestFiniteMagnitude
    private var lastX: Double = 0
    private var lastY: Double = 0
    private var count: Int = 0

    public init(interval: Double = 0.5, maxDistance: Double = 4) {
        self.interval = interval
        self.maxDistance = maxDistance
    }

    /// Call on every button-down; returns the click count to put on both down and up events.
    public mutating func registerDown(button: Int, x: Double, y: Double, time: Double) -> Int {
        let close = abs(x - lastX) <= maxDistance && abs(y - lastY) <= maxDistance
        if button == lastButton && close && time - lastTime <= interval && time >= lastTime {
            count += 1
        } else {
            count = 1
        }
        lastButton = button
        lastTime = time
        lastX = x
        lastY = y
        return count
    }

    public mutating func reset() {
        lastButton = -1
        lastTime = -Double.greatestFiniteMagnitude
        count = 0
    }
}

/// Exponential restart back-off for the helper process: 1, 2, 4 … 30 s;
/// resets once the helper has stayed up for a while.
public struct RestartBackoff: Sendable {
    public let initial: Double
    public let maximum: Double
    public let stableAfter: Double
    private var next: Double

    public init(initial: Double = 1, maximum: Double = 30, stableAfter: Double = 60) {
        self.initial = initial
        self.maximum = maximum
        self.stableAfter = stableAfter
        self.next = initial
    }

    /// Delay before the next restart. `uptime` = how long the process ran before exiting.
    public mutating func delay(afterUptime uptime: Double) -> Double {
        if uptime >= stableAfter { next = initial }
        let d = next
        next = min(next * 2, maximum)
        return d
    }

    public mutating func reset() { next = initial }
}
