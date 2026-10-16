import Foundation

/// CGEventFlags-compatible modifier bits (raw values identical to CoreGraphics'
/// `CGEventFlags` and IOKit's NX_DEVICE*KEYMASK), kept here so HRCore stays Foundation-only.
public struct ModifierFlags: OptionSet, Hashable, Sendable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }

    // Device-independent (CGEventFlags)
    public static let capsLock = ModifierFlags(rawValue: 0x0001_0000)     // maskAlphaShift
    public static let shift = ModifierFlags(rawValue: 0x0002_0000)        // maskShift
    public static let control = ModifierFlags(rawValue: 0x0004_0000)      // maskControl
    public static let option = ModifierFlags(rawValue: 0x0008_0000)       // maskAlternate
    public static let command = ModifierFlags(rawValue: 0x0010_0000)      // maskCommand
    public static let numericPad = ModifierFlags(rawValue: 0x0020_0000)   // maskNumericPad
    public static let help = ModifierFlags(rawValue: 0x0040_0000)         // maskHelp
    public static let function = ModifierFlags(rawValue: 0x0080_0000)     // maskSecondaryFn

    // Device-dependent left/right bits (IOLLEvent.h)
    public static let leftControl = ModifierFlags(rawValue: 0x0000_0001)
    public static let leftShift = ModifierFlags(rawValue: 0x0000_0002)
    public static let rightShift = ModifierFlags(rawValue: 0x0000_0004)
    public static let leftCommand = ModifierFlags(rawValue: 0x0000_0008)
    public static let rightCommand = ModifierFlags(rawValue: 0x0000_0010)
    public static let leftOption = ModifierFlags(rawValue: 0x0000_0020)
    public static let rightOption = ModifierFlags(rawValue: 0x0000_0040)
    public static let rightControl = ModifierFlags(rawValue: 0x0000_2000)
}

/// DOM `KeyboardEvent.code` → macOS virtual key code (kVK_* from Carbon's Events.h).
/// Codes describe physical key positions, so the Mac's own keyboard layout decides the character.
public enum KeyCodeMap {
    /// One entry per distinct physical key.
    public static let virtualKeys: [String: UInt16] = [
        // Letters
        "KeyA": 0x00, "KeyS": 0x01, "KeyD": 0x02, "KeyF": 0x03, "KeyH": 0x04, "KeyG": 0x05,
        "KeyZ": 0x06, "KeyX": 0x07, "KeyC": 0x08, "KeyV": 0x09, "KeyB": 0x0B, "KeyQ": 0x0C,
        "KeyW": 0x0D, "KeyE": 0x0E, "KeyR": 0x0F, "KeyY": 0x10, "KeyT": 0x11, "KeyO": 0x1F,
        "KeyU": 0x20, "KeyI": 0x22, "KeyP": 0x23, "KeyL": 0x25, "KeyJ": 0x26, "KeyK": 0x28,
        "KeyN": 0x2D, "KeyM": 0x2E,
        // Digits (top row)
        "Digit1": 0x12, "Digit2": 0x13, "Digit3": 0x14, "Digit4": 0x15, "Digit5": 0x17,
        "Digit6": 0x16, "Digit7": 0x1A, "Digit8": 0x1C, "Digit9": 0x19, "Digit0": 0x1D,
        // Punctuation
        "Minus": 0x1B, "Equal": 0x18, "BracketLeft": 0x21, "BracketRight": 0x1E,
        "Backslash": 0x2A, "Semicolon": 0x29, "Quote": 0x27, "Backquote": 0x32,
        "Comma": 0x2B, "Period": 0x2F, "Slash": 0x2C,
        // International / JIS
        "IntlBackslash": 0x0A,   // kVK_ISO_Section
        "IntlYen": 0x5D,         // kVK_JIS_Yen
        "IntlRo": 0x5E,          // kVK_JIS_Underscore
        "Lang1": 0x68,           // kVK_JIS_Kana
        "Lang2": 0x66,           // kVK_JIS_Eisu
        "NumpadComma": 0x5F,     // kVK_JIS_KeypadComma
        // Whitespace / editing
        "Enter": 0x24, "Tab": 0x30, "Space": 0x31, "Backspace": 0x33, "Escape": 0x35,
        "Delete": 0x75,          // forward delete
        "Help": 0x72,            // Help / Insert position
        "ContextMenu": 0x6E,     // kVK_ContextualMenu
        // Modifiers
        "ShiftLeft": 0x38, "ShiftRight": 0x3C,
        "ControlLeft": 0x3B, "ControlRight": 0x3E,
        "AltLeft": 0x3A, "AltRight": 0x3D,
        "MetaLeft": 0x37, "MetaRight": 0x36,
        "CapsLock": 0x39, "Fn": 0x3F,
        // Navigation
        "ArrowLeft": 0x7B, "ArrowRight": 0x7C, "ArrowDown": 0x7D, "ArrowUp": 0x7E,
        "Home": 0x73, "End": 0x77, "PageUp": 0x74, "PageDown": 0x79,
        // Function keys
        "F1": 0x7A, "F2": 0x78, "F3": 0x63, "F4": 0x76, "F5": 0x60, "F6": 0x61,
        "F7": 0x62, "F8": 0x64, "F9": 0x65, "F10": 0x6D, "F11": 0x67, "F12": 0x6F,
        "F13": 0x69, "F14": 0x6B, "F15": 0x71, "F16": 0x6A, "F17": 0x40, "F18": 0x4F,
        "F19": 0x50, "F20": 0x5A,
        // Keypad
        "Numpad0": 0x52, "Numpad1": 0x53, "Numpad2": 0x54, "Numpad3": 0x55, "Numpad4": 0x56,
        "Numpad5": 0x57, "Numpad6": 0x58, "Numpad7": 0x59, "Numpad8": 0x5B, "Numpad9": 0x5C,
        "NumpadDecimal": 0x41, "NumpadMultiply": 0x43, "NumpadAdd": 0x45, "NumpadSubtract": 0x4E,
        "NumpadDivide": 0x4B, "NumpadEnter": 0x4C, "NumpadEqual": 0x51,
        "NumLock": 0x47,         // kVK_ANSI_KeypadClear (the Mac "Clear" key)
        // Media keys that have virtual key codes
        "AudioVolumeUp": 0x48, "AudioVolumeDown": 0x49, "AudioVolumeMute": 0x4A,
    ]

    /// Alternative DOM names that map onto the same physical Mac key.
    public static let aliases: [String: String] = [
        "OSLeft": "MetaLeft",        // older Firefox
        "OSRight": "MetaRight",
        "Insert": "Help",            // PC keyboards on a Mac: Insert sends Help
        "NumpadClear": "NumLock",
        "PrintScreen": "F13",        // common PC → Mac convention
        "ScrollLock": "F14",
        "Pause": "F15",
        "KanaMode": "Lang1",
        "Convert": "Lang1",
        "NonConvert": "Lang2",
        "VolumeUp": "AudioVolumeUp", // older Chrome names
        "VolumeDown": "AudioVolumeDown",
        "VolumeMute": "AudioVolumeMute",
    ]

    /// System-defined media keys (NX_KEYTYPE_* from IOKit's ev_keymap.h). These are posted as
    /// NSEvent `.systemDefined` events (subtype 8) instead of key codes.
    public static let mediaKeys: [String: Int32] = [
        "AudioVolumeUp": 0,          // NX_KEYTYPE_SOUND_UP
        "AudioVolumeDown": 1,        // NX_KEYTYPE_SOUND_DOWN
        "BrightnessUp": 2,           // NX_KEYTYPE_BRIGHTNESS_UP
        "BrightnessDown": 3,         // NX_KEYTYPE_BRIGHTNESS_DOWN
        "AudioVolumeMute": 7,        // NX_KEYTYPE_MUTE
        "Eject": 14,                 // NX_KEYTYPE_EJECT
        "MediaPlayPause": 16,        // NX_KEYTYPE_PLAY
        "MediaTrackNext": 17,        // NX_KEYTYPE_NEXT
        "MediaTrackPrevious": 18,    // NX_KEYTYPE_PREVIOUS
        "MediaFastForward": 19,      // NX_KEYTYPE_FAST
        "MediaRewind": 20,           // NX_KEYTYPE_REWIND
    ]

    /// Resolves aliases to the canonical DOM code used in `virtualKeys`.
    public static func canonical(_ code: String) -> String {
        aliases[code] ?? code
    }

    public static func keyCode(for code: String) -> UInt16? {
        virtualKeys[canonical(code)]
    }

    public static func mediaKey(for code: String) -> Int32? {
        mediaKeys[canonical(code)]
    }

    /// Modifier bits a modifier key contributes while held (nil for non-modifier keys).
    public static func modifierFlags(for code: String) -> ModifierFlags? {
        switch canonical(code) {
        case "ShiftLeft": return [.shift, .leftShift]
        case "ShiftRight": return [.shift, .rightShift]
        case "ControlLeft": return [.control, .leftControl]
        case "ControlRight": return [.control, .rightControl]
        case "AltLeft": return [.option, .leftOption]
        case "AltRight": return [.option, .rightOption]
        case "MetaLeft": return [.command, .leftCommand]
        case "MetaRight": return [.command, .rightCommand]
        case "CapsLock": return .capsLock
        case "Fn": return .function
        default: return nil
        }
    }

    public static func isModifier(_ code: String) -> Bool {
        modifierFlags(for: code) != nil
    }

    /// Flags real Mac hardware sets on its own for some keys (arrows and keypad set
    /// NumericPad; arrows, navigation and F-keys set SecondaryFn).
    public static func intrinsicFlags(for code: String) -> ModifierFlags {
        let c = canonical(code)
        switch c {
        case "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown":
            return [.numericPad, .function]
        case "Home", "End", "PageUp", "PageDown", "Delete", "Help":
            return .function
        default:
            if c.hasPrefix("Numpad") || c == "NumLock" { return .numericPad }
            if c.count >= 2, c.hasPrefix("F"), Int(c.dropFirst()) != nil { return .function }
            return []
        }
    }
}

/// Splits text into chunks for `CGEvent.keyboardSetUnicodeString`, which only takes
/// a handful of UTF-16 units per event. Never splits a character (or surrogate pair).
public enum TextChunker {
    public static let maxTextLength = 4096

    public static func chunks(_ text: String, maxUTF16: Int = 20) -> [[UInt16]] {
        let limit = max(2, maxUTF16)
        var result: [[UInt16]] = []
        var current: [UInt16] = []
        for character in text.prefix(maxTextLength) {
            let units = Array(String(character).utf16)
            if !current.isEmpty && current.count + units.count > limit {
                result.append(current)
                current = []
            }
            if units.count > limit {
                // An extremely long grapheme cluster: split by scalar so nothing is lost.
                for scalar in character.unicodeScalars {
                    let scalarUnits = Array(String(scalar).utf16)
                    if !current.isEmpty && current.count + scalarUnits.count > limit {
                        result.append(current)
                        current = []
                    }
                    current.append(contentsOf: scalarUnits)
                }
            } else {
                current.append(contentsOf: units)
            }
        }
        if !current.isEmpty { result.append(current) }
        return result
    }
}
