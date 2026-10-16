import AppKit
import ApplicationServices
import CoreGraphics
import Foundation
import HRCore

/// Injects the remote user's mouse and keyboard input with CGEvent (needs Accessibility).
/// Everything runs on a private serial queue.
final class InputInjector: @unchecked Sendable {
    /// Called (rate-limited) when input arrives but Accessibility is not granted.
    var onBlockedByPermission: (@Sendable () -> Void)?

    private let queue = DispatchQueue(label: "org.heartfulness.remote.input", qos: .userInteractive)
    private let source = CGEventSource(stateID: .hidSystemState)

    private var enabled = true
    private var defaultDisplay: CGDirectDisplayID = CGMainDisplayID()
    private var pressedButtons: Set<Int> = []
    private var buttonClickCounts: [Int: Int] = [:]
    private var pressedKeys: [String: CGKeyCode] = [:]
    private var heldModifiers: Set<String> = []
    private var capsLockOn = false
    private var clickCounter: ClickCounter
    private var lastPoint = CGPoint.zero
    private var scrollRemainderX = 0.0
    private var scrollRemainderY = 0.0
    private var trusted = false
    private var lastTrustCheck: Double = -100
    private var lastBlockedReport: Double = -100

    init() {
        clickCounter = ClickCounter(interval: NSEvent.doubleClickInterval, maxDistance: 4)
    }

    // MARK: Public API (any thread)

    func handle(_ message: InputMessage) {
        queue.async { self.process(message) }
    }

    func setDefaultDisplay(_ id: CGDirectDisplayID) {
        queue.async { self.defaultDisplay = id }
    }

    /// Disabled while the kill switch is on: all input is dropped and held keys released.
    func setEnabled(_ value: Bool) {
        queue.async {
            if !value { self.releaseEverything() }
            self.enabled = value
        }
    }

    func reset() {
        queue.async { self.releaseEverything() }
    }

    // MARK: Dispatch

    private func process(_ message: InputMessage) {
        guard enabled else { return }
        if message.kind == .reset {
            releaseEverything()
            return
        }
        guard isTrusted() else {
            reportBlocked()
            return
        }
        let display = message.displayID ?? defaultDisplay
        switch message.kind {
        case .move:
            if let p = point(message, display: display) { move(to: p) }
        case .button:
            guard let domButton = message.b, let down = message.d else { return }
            pressButton(domButton, down: down, at: point(message, display: display))
        case .wheel:
            wheel(dx: message.dx ?? 0, dy: message.dy ?? 0, at: point(message, display: display))
        case .key:
            guard let code = message.c, let down = message.d else { return }
            pressKey(code, down: down)
        case .text:
            if let text = message.s { typeText(text) }
        case .reset, .unknown:
            break
        }
    }

    private func isTrusted() -> Bool {
        let now = ProcessInfo.processInfo.systemUptime
        if now - lastTrustCheck > 2 {
            trusted = AXIsProcessTrusted()
            lastTrustCheck = now
        }
        return trusted
    }

    private func reportBlocked() {
        let now = ProcessInfo.processInfo.systemUptime
        guard now - lastBlockedReport > 30 else { return }
        lastBlockedReport = now
        Log.input.error("Input dropped: Accessibility permission is not granted")
        onBlockedByPermission?()
    }

    private func point(_ message: InputMessage, display: CGDirectDisplayID) -> CGPoint? {
        guard let x = message.x, let y = message.y else { return nil }
        var bounds = CGDisplayBounds(display)
        if bounds.width <= 0 || bounds.height <= 0 { bounds = CGDisplayBounds(CGMainDisplayID()) }
        let rect = DisplayRect(x: Double(bounds.origin.x), y: Double(bounds.origin.y),
                               width: Double(bounds.size.width), height: Double(bounds.size.height))
        let mapped = CoordinateMapper.point(normalizedX: x, normalizedY: y, in: rect)
        return CGPoint(x: mapped.x, y: mapped.y)
    }

    // MARK: Mouse

    private func currentFlags() -> CGEventFlags {
        var flags = ModifierFlags()
        for code in heldModifiers {
            if let m = KeyCodeMap.modifierFlags(for: code) { flags.formUnion(m) }
        }
        if capsLockOn { flags.insert(.capsLock) }
        return CGEventFlags(rawValue: flags.rawValue)
    }

    /// DOM button → CG button number (0 left, 1 right, 2 middle, 3 back, 4 forward).
    private func cgButtonNumber(_ domButton: Int) -> Int {
        switch domButton {
        case 0: return 0
        case 1: return 2
        case 2: return 1
        default: return max(3, domButton)
        }
    }

    private func move(to p: CGPoint) {
        lastPoint = p
        let type: CGEventType
        let button: CGMouseButton
        var otherNumber: Int?
        if pressedButtons.contains(0) {
            type = .leftMouseDragged
            button = .left
        } else if pressedButtons.contains(2) {
            type = .rightMouseDragged
            button = .right
        } else if let other = pressedButtons.sorted().first {
            type = .otherMouseDragged
            button = .center
            otherNumber = cgButtonNumber(other)
        } else {
            type = .mouseMoved
            button = .left
        }
        guard let event = CGEvent(mouseEventSource: source, mouseType: type, mouseCursorPosition: p, mouseButton: button) else { return }
        if let otherNumber { event.setIntegerValueField(.mouseEventButtonNumber, value: Int64(otherNumber)) }
        event.flags = currentFlags()
        event.post(tap: .cghidEventTap)
    }

    private func pressButton(_ domButton: Int, down: Bool, at target: CGPoint?) {
        if let target, target != lastPoint { move(to: target) }
        let position = target ?? lastPoint
        let number = cgButtonNumber(domButton)

        let clickCount: Int
        if down {
            guard !pressedButtons.contains(domButton) else { return }
            pressedButtons.insert(domButton)
            clickCount = clickCounter.registerDown(button: domButton, x: Double(position.x), y: Double(position.y),
                                                   time: ProcessInfo.processInfo.systemUptime)
            buttonClickCounts[domButton] = clickCount
        } else {
            guard pressedButtons.contains(domButton) else { return }
            pressedButtons.remove(domButton)
            clickCount = buttonClickCounts.removeValue(forKey: domButton) ?? 1
        }

        let type: CGEventType
        let cgButton: CGMouseButton
        switch number {
        case 0:
            type = down ? .leftMouseDown : .leftMouseUp
            cgButton = .left
        case 1:
            type = down ? .rightMouseDown : .rightMouseUp
            cgButton = .right
        default:
            type = down ? .otherMouseDown : .otherMouseUp
            cgButton = .center
        }
        guard let event = CGEvent(mouseEventSource: source, mouseType: type, mouseCursorPosition: position, mouseButton: cgButton) else { return }
        event.setIntegerValueField(.mouseEventClickState, value: Int64(clickCount))
        if number >= 2 { event.setIntegerValueField(.mouseEventButtonNumber, value: Int64(number)) }
        event.flags = currentFlags()
        event.post(tap: .cghidEventTap)
    }

    private func wheel(dx: Double, dy: Double, at target: CGPoint?) {
        if let target, target != lastPoint { move(to: target) }
        guard dx.isFinite, dy.isFinite else { return }
        // DOM: deltaY > 0 scrolls down. CG: positive wheel1 scrolls up. Hence the minus signs.
        scrollRemainderY += -dy
        scrollRemainderX += -dx
        let stepY = scrollRemainderY.rounded(.towardZero)
        let stepX = scrollRemainderX.rounded(.towardZero)
        scrollRemainderY -= stepY
        scrollRemainderX -= stepX
        let wheelY = Int32(max(-10_000, min(10_000, stepY)))
        let wheelX = Int32(max(-10_000, min(10_000, stepX)))
        guard wheelX != 0 || wheelY != 0 else { return }
        guard let event = CGEvent(scrollWheelEvent2Source: source, units: .pixel, wheelCount: 2,
                                  wheel1: wheelY, wheel2: wheelX, wheel3: 0) else { return }
        event.setIntegerValueField(.scrollWheelEventIsContinuous, value: 1)
        event.location = lastPoint
        event.flags = currentFlags()
        event.post(tap: .cghidEventTap)
    }

    // MARK: Keyboard

    private func pressKey(_ code: String, down: Bool) {
        if let media = KeyCodeMap.mediaKey(for: code) {
            postMediaKey(media, down: down)
            return
        }
        guard let keyCode = KeyCodeMap.keyCode(for: code) else {
            Log.input.debug("No Mac key for code \(code, privacy: .public)")
            return
        }
        let canonical = KeyCodeMap.canonical(code)

        if KeyCodeMap.isModifier(canonical) {
            if canonical == "CapsLock" {
                if down { capsLockOn.toggle() }
            } else if down {
                heldModifiers.insert(canonical)
            } else {
                heldModifiers.remove(canonical)
            }
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: keyCode, keyDown: down) else { return }
            event.type = .flagsChanged
            event.flags = currentFlags()
            event.post(tap: .cghidEventTap)
            return
        }

        if down {
            pressedKeys[canonical] = keyCode
        } else {
            pressedKeys.removeValue(forKey: canonical)
        }
        guard let event = CGEvent(keyboardEventSource: source, virtualKey: keyCode, keyDown: down) else { return }
        let intrinsic = CGEventFlags(rawValue: KeyCodeMap.intrinsicFlags(for: canonical).rawValue)
        event.flags = currentFlags().union(intrinsic)
        event.post(tap: .cghidEventTap)
    }

    /// Play/pause, next/previous, volume and brightness are "system-defined" events.
    private func postMediaKey(_ keyType: Int32, down: Bool) {
        let state: Int32 = down ? 0xA : 0xB
        let data1 = Int((keyType << 16) | (state << 8))
        let flags = NSEvent.ModifierFlags(rawValue: down ? 0xA00 : 0xB00)
        DispatchQueue.main.async {
            guard let event = NSEvent.otherEvent(with: .systemDefined, location: .zero, modifierFlags: flags,
                                                 timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: 0,
                                                 context: nil, subtype: 8, data1: data1, data2: -1) else { return }
            event.cgEvent?.post(tap: .cghidEventTap)
        }
    }

    private func typeText(_ text: String) {
        for chunk in TextChunker.chunks(text, maxUTF16: 20) {
            guard let down = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
                  let up = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false) else { continue }
            down.keyboardSetUnicodeString(stringLength: chunk.count, unicodeString: chunk)
            up.keyboardSetUnicodeString(stringLength: chunk.count, unicodeString: chunk)
            down.flags = []
            up.flags = []
            down.post(tap: .cghidEventTap)
            up.post(tap: .cghidEventTap)
        }
    }

    // MARK: Reset

    private func releaseEverything() {
        for domButton in pressedButtons.sorted() {
            let number = cgButtonNumber(domButton)
            let type: CGEventType = number == 0 ? .leftMouseUp : (number == 1 ? .rightMouseUp : .otherMouseUp)
            let cgButton: CGMouseButton = number == 0 ? .left : (number == 1 ? .right : .center)
            if let event = CGEvent(mouseEventSource: source, mouseType: type, mouseCursorPosition: lastPoint, mouseButton: cgButton) {
                if number >= 2 { event.setIntegerValueField(.mouseEventButtonNumber, value: Int64(number)) }
                event.post(tap: .cghidEventTap)
            }
        }
        pressedButtons.removeAll()
        buttonClickCounts.removeAll()

        for (_, keyCode) in pressedKeys {
            if let event = CGEvent(keyboardEventSource: source, virtualKey: keyCode, keyDown: false) {
                event.flags = []
                event.post(tap: .cghidEventTap)
            }
        }
        pressedKeys.removeAll()

        let modifiers = heldModifiers
        heldModifiers.removeAll()
        for code in modifiers {
            guard let keyCode = KeyCodeMap.keyCode(for: code),
                  let event = CGEvent(keyboardEventSource: source, virtualKey: keyCode, keyDown: false) else { continue }
            event.type = .flagsChanged
            event.flags = currentFlags()
            event.post(tap: .cghidEventTap)
        }
        scrollRemainderX = 0
        scrollRemainderY = 0
        clickCounter.reset()
    }
}
