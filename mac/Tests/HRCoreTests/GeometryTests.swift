import XCTest
@testable import HRCore

final class GeometryTests: XCTestCase {
    func testMapsCornersAndCentreOnMainDisplay() {
        let main = DisplayRect(x: 0, y: 0, width: 1512, height: 982)
        XCTAssertEqual(CoordinateMapper.point(normalizedX: 0, normalizedY: 0, in: main), DisplayPoint(x: 0, y: 0))
        XCTAssertEqual(CoordinateMapper.point(normalizedX: 0.5, normalizedY: 0.5, in: main), DisplayPoint(x: 756, y: 491))
        // 1.0 stays on this display (last point), never the neighbour's first point.
        XCTAssertEqual(CoordinateMapper.point(normalizedX: 1, normalizedY: 1, in: main), DisplayPoint(x: 1511, y: 981))
    }

    func testMapsOntoSecondaryDisplayWithNegativeOrigin() {
        let left = DisplayRect(x: -1920, y: -200, width: 1920, height: 1080)
        XCTAssertEqual(CoordinateMapper.point(normalizedX: 0, normalizedY: 0, in: left), DisplayPoint(x: -1920, y: -200))
        XCTAssertEqual(CoordinateMapper.point(normalizedX: 0.25, normalizedY: 0.5, in: left), DisplayPoint(x: -1440, y: 340))
        XCTAssertEqual(CoordinateMapper.point(normalizedX: 1, normalizedY: 1, in: left), DisplayPoint(x: -1, y: 879))
    }

    func testClampsOutOfRangeAndInvalidInput() {
        let r = DisplayRect(x: 100, y: 50, width: 800, height: 600)
        XCTAssertEqual(CoordinateMapper.point(normalizedX: -3, normalizedY: 7, in: r), DisplayPoint(x: 100, y: 649))
        XCTAssertEqual(CoordinateMapper.point(normalizedX: .nan, normalizedY: .infinity, in: r), DisplayPoint(x: 100, y: 50))
        let zero = DisplayRect(x: 10, y: 10, width: 0, height: 0)
        XCTAssertEqual(CoordinateMapper.point(normalizedX: 0.7, normalizedY: 0.7, in: zero), DisplayPoint(x: 10, y: 10))
    }

    func testNormalizedRoundTrip() {
        let r = DisplayRect(x: 1512, y: 0, width: 2560, height: 1440)
        let p = CoordinateMapper.point(normalizedX: 0.3, normalizedY: 0.6, in: r)
        let back = CoordinateMapper.normalized(p, in: r)
        XCTAssertEqual(back.x, 0.3, accuracy: 1e-9)
        XCTAssertEqual(back.y, 0.6, accuracy: 1e-9)
    }

    private func assertSize(_ pw: Int, _ ph: Int, _ ew: Int, _ eh: Int, file: StaticString = #filePath, line: UInt = #line) {
        let s = CaptureSizing.outputSize(pixelWidth: pw, pixelHeight: ph)
        XCTAssertEqual(s.width, ew, file: file, line: line)
        XCTAssertEqual(s.height, eh, file: file, line: line)
    }

    func testCaptureSizing() {
        assertSize(5120, 2880, 3840, 2160)
        assertSize(3024, 1964, 3024, 1964)
        assertSize(1001, 501, 1000, 500)
        assertSize(6016, 3384, 3840, 2160)
        assertSize(2160, 3840, 2160, 3840)
        assertSize(0, 1, 2, 2)
    }

    func testClickCounter() {
        var c = ClickCounter(interval: 0.5, maxDistance: 4)
        XCTAssertEqual(c.registerDown(button: 0, x: 10, y: 10, time: 1.0), 1)
        XCTAssertEqual(c.registerDown(button: 0, x: 12, y: 11, time: 1.3), 2)
        XCTAssertEqual(c.registerDown(button: 0, x: 12, y: 11, time: 1.6), 3)
        // Too slow → starts again.
        XCTAssertEqual(c.registerDown(button: 0, x: 12, y: 11, time: 3.0), 1)
        // Moved too far → starts again.
        XCTAssertEqual(c.registerDown(button: 0, x: 40, y: 11, time: 3.1), 1)
        // Different button → starts again.
        XCTAssertEqual(c.registerDown(button: 2, x: 40, y: 11, time: 3.2), 1)
        c.reset()
        XCTAssertEqual(c.registerDown(button: 2, x: 40, y: 11, time: 3.3), 1)
    }

    func testRestartBackoff() {
        var b = RestartBackoff(initial: 1, maximum: 30, stableAfter: 60)
        XCTAssertEqual(b.delay(afterUptime: 0.1), 1)
        XCTAssertEqual(b.delay(afterUptime: 0.1), 2)
        XCTAssertEqual(b.delay(afterUptime: 0.1), 4)
        XCTAssertEqual(b.delay(afterUptime: 0.1), 8)
        XCTAssertEqual(b.delay(afterUptime: 0.1), 16)
        XCTAssertEqual(b.delay(afterUptime: 0.1), 30)
        XCTAssertEqual(b.delay(afterUptime: 0.1), 30)
        // Ran for a long time → back to the start.
        XCTAssertEqual(b.delay(afterUptime: 3600), 1)
        b.reset()
        XCTAssertEqual(b.delay(afterUptime: 0), 1)
    }

    func testAppPlacement() {
        let home = "/Users/owner"
        XCTAssertTrue(AppPlacement.isInApplicationsFolder(bundlePath: "/Applications/Heartfulness Remote.app", homeDirectory: home))
        XCTAssertTrue(AppPlacement.isInApplicationsFolder(bundlePath: "/Users/owner/Applications/Heartfulness Remote.app", homeDirectory: home))
        XCTAssertTrue(AppPlacement.isInApplicationsFolder(bundlePath: "/Users/owner/Applications/Tools/Heartfulness Remote.app/", homeDirectory: home + "/"))
        XCTAssertFalse(AppPlacement.isInApplicationsFolder(bundlePath: "/Users/owner/Downloads/Heartfulness Remote/Heartfulness Remote.app", homeDirectory: home))
        XCTAssertFalse(AppPlacement.isInApplicationsFolder(bundlePath: "/Applications Old/Heartfulness Remote.app", homeDirectory: home))
        XCTAssertTrue(AppPlacement.isTranslocated(bundlePath: "/private/var/folders/xy/T/AppTranslocation/ABC/d/Heartfulness Remote.app"))
        XCTAssertFalse(AppPlacement.isTranslocated(bundlePath: "/Applications/Heartfulness Remote.app"))
        XCTAssertEqual(AppPlacement.destination(bundleName: "Heartfulness Remote.app", homeDirectory: home),
                       "/Users/owner/Applications/Heartfulness Remote.app")
    }
}
