import XCTest
@testable import HRCore

final class KeyCodeTests: XCTestCase {
    func testAllLettersDigitsAndFunctionKeysPresent() {
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
            XCTAssertNotNil(KeyCodeMap.keyCode(for: "Key\(letter)"), "Key\(letter)")
        }
        for digit in 0...9 {
            XCTAssertNotNil(KeyCodeMap.keyCode(for: "Digit\(digit)"), "Digit\(digit)")
            XCTAssertNotNil(KeyCodeMap.keyCode(for: "Numpad\(digit)"), "Numpad\(digit)")
        }
        for f in 1...20 {
            XCTAssertNotNil(KeyCodeMap.keyCode(for: "F\(f)"), "F\(f)")
        }
    }

    func testCommonCodesPresent() {
        let codes = [
            "Enter", "Tab", "Space", "Backspace", "Escape", "Delete", "Insert", "Help", "ContextMenu",
            "ShiftLeft", "ShiftRight", "ControlLeft", "ControlRight", "AltLeft", "AltRight",
            "MetaLeft", "MetaRight", "OSLeft", "OSRight", "CapsLock", "Fn",
            "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End", "PageUp", "PageDown",
            "Minus", "Equal", "BracketLeft", "BracketRight", "Backslash", "Semicolon", "Quote",
            "Backquote", "Comma", "Period", "Slash",
            "IntlBackslash", "IntlRo", "IntlYen", "Lang1", "Lang2", "KanaMode", "NumpadComma",
            "NumpadDecimal", "NumpadMultiply", "NumpadAdd", "NumpadSubtract", "NumpadDivide",
            "NumpadEnter", "NumpadEqual", "NumLock",
            "AudioVolumeUp", "AudioVolumeDown", "AudioVolumeMute",
        ]
        for code in codes {
            XCTAssertNotNil(KeyCodeMap.keyCode(for: code), code)
        }
    }

    func testKnownValues() {
        XCTAssertEqual(KeyCodeMap.keyCode(for: "KeyA"), 0x00)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "KeyZ"), 0x06)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "KeyQ"), 0x0C)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "Digit0"), 0x1D)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "Enter"), 0x24)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "Backspace"), 0x33)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "Delete"), 0x75)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "Escape"), 0x35)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "MetaLeft"), 0x37)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "MetaRight"), 0x36)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "ArrowUp"), 0x7E)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "F1"), 0x7A)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "F12"), 0x6F)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "IntlBackslash"), 0x0A)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "IntlYen"), 0x5D)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "IntlRo"), 0x5E)
        XCTAssertEqual(KeyCodeMap.keyCode(for: "Insert"), KeyCodeMap.keyCode(for: "Help"))
        XCTAssertNil(KeyCodeMap.keyCode(for: "NotAKey"))
        XCTAssertNil(KeyCodeMap.keyCode(for: ""))
    }

    func testNoDuplicateKeyCodesForDistinctKeys() {
        var seen: [UInt16: String] = [:]
        for (code, vk) in KeyCodeMap.virtualKeys {
            if let other = seen[vk] {
                XCTFail("\(code) and \(other) share key code \(vk)")
            }
            seen[vk] = code
        }
        // Aliases must point at canonical entries, never at other aliases or missing keys.
        for (alias, target) in KeyCodeMap.aliases {
            XCTAssertNil(KeyCodeMap.virtualKeys[alias], "\(alias) is both an alias and a key")
            XCTAssertNotNil(KeyCodeMap.virtualKeys[target], "\(alias) → \(target) missing")
        }
    }

    func testAllKeyCodesAreValidMacKeyCodes() {
        for (code, vk) in KeyCodeMap.virtualKeys {
            XCTAssertLessThanOrEqual(vk, 0x7F, code)
        }
    }

    func testModifierFlags() {
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "ShiftLeft"), [.shift, .leftShift])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "ShiftRight"), [.shift, .rightShift])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "ControlLeft"), [.control, .leftControl])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "ControlRight"), [.control, .rightControl])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "AltLeft"), [.option, .leftOption])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "AltRight"), [.option, .rightOption])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "MetaLeft"), [.command, .leftCommand])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "OSRight"), [.command, .rightCommand])
        XCTAssertEqual(KeyCodeMap.modifierFlags(for: "CapsLock"), .capsLock)
        XCTAssertNil(KeyCodeMap.modifierFlags(for: "KeyA"))
        XCTAssertTrue(KeyCodeMap.isModifier("Fn"))
        XCTAssertFalse(KeyCodeMap.isModifier("Space"))
        // Raw values must equal CoreGraphics' CGEventFlags.
        XCTAssertEqual(ModifierFlags.shift.rawValue, 0x20000)
        XCTAssertEqual(ModifierFlags.control.rawValue, 0x40000)
        XCTAssertEqual(ModifierFlags.option.rawValue, 0x80000)
        XCTAssertEqual(ModifierFlags.command.rawValue, 0x100000)
        XCTAssertEqual(ModifierFlags.function.rawValue, 0x800000)
    }

    func testIntrinsicFlags() {
        XCTAssertEqual(KeyCodeMap.intrinsicFlags(for: "ArrowLeft"), [.numericPad, .function])
        XCTAssertEqual(KeyCodeMap.intrinsicFlags(for: "Home"), .function)
        XCTAssertEqual(KeyCodeMap.intrinsicFlags(for: "Insert"), .function)
        XCTAssertEqual(KeyCodeMap.intrinsicFlags(for: "F5"), .function)
        XCTAssertEqual(KeyCodeMap.intrinsicFlags(for: "Numpad5"), .numericPad)
        XCTAssertEqual(KeyCodeMap.intrinsicFlags(for: "KeyF"), [])
        XCTAssertEqual(KeyCodeMap.intrinsicFlags(for: "Fn"), [])
    }

    func testMediaKeys() {
        XCTAssertEqual(KeyCodeMap.mediaKey(for: "MediaPlayPause"), 16)
        XCTAssertEqual(KeyCodeMap.mediaKey(for: "MediaTrackNext"), 17)
        XCTAssertEqual(KeyCodeMap.mediaKey(for: "MediaTrackPrevious"), 18)
        XCTAssertEqual(KeyCodeMap.mediaKey(for: "AudioVolumeMute"), 7)
        XCTAssertEqual(KeyCodeMap.mediaKey(for: "VolumeUp"), 0)
        XCTAssertNil(KeyCodeMap.mediaKey(for: "KeyA"))
    }

    func testTextChunker() {
        XCTAssertEqual(TextChunker.chunks(""), [])
        XCTAssertEqual(TextChunker.chunks("abc"), [Array("abc".utf16)])
        let long = String(repeating: "x", count: 45)
        let chunks = TextChunker.chunks(long)
        XCTAssertEqual(chunks.map { $0.count }, [20, 20, 5])
        // Emoji (surrogate pairs) are never split.
        let emoji = String(repeating: "😀", count: 15)   // 30 UTF-16 units
        let emojiChunks = TextChunker.chunks(emoji)
        XCTAssertEqual(emojiChunks.map { $0.count }, [20, 10])
        for chunk in emojiChunks {
            XCTAssertFalse(String(decoding: chunk, as: UTF16.self).contains("\u{FFFD}"))
            XCTAssertFalse(UTF16.isTrailSurrogate(chunk[0]))
        }
        XCTAssertEqual(emojiChunks.flatMap { $0 }, Array(emoji.utf16))
        // Overlong input is capped.
        XCTAssertEqual(TextChunker.chunks(String(repeating: "a", count: 10_000)).flatMap { $0 }.count, TextChunker.maxTextLength)
    }
}
