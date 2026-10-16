import Carbon
import Foundation

/// System-wide ⌃⌥⌘K kill-switch shortcut via Carbon's RegisterEventHotKey
/// (works without Accessibility permission).
final class GlobalHotKey {
    private var hotKeyRef: EventHotKeyRef?
    private var handlerRef: EventHandlerRef?
    private var action: (@MainActor () -> Void)?

    /// Registers ⌃⌥⌘K. Returns false if another app already owns the shortcut.
    @discardableResult
    func registerKillShortcut(action: @escaping @MainActor () -> Void) -> Bool {
        unregister()
        self.action = action

        var eventType = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let context = Unmanaged.passUnretained(self).toOpaque()
        let installStatus = InstallEventHandler(
            GetApplicationEventTarget(),
            { _, _, userData -> OSStatus in
                guard let userData else { return OSStatus(eventNotHandledErr) }
                let hotKey = Unmanaged<GlobalHotKey>.fromOpaque(userData).takeUnretainedValue()
                hotKey.fire()
                return 0
            },
            1,
            &eventType,
            context,
            &handlerRef
        )
        guard installStatus == 0 else {
            Log.app.error("InstallEventHandler failed: \(installStatus, privacy: .public)")
            return false
        }

        let hotKeyID = EventHotKeyID(signature: OSType(0x4852_4B53), id: 1)   // 'HRKS'
        let modifiers = UInt32(controlKey | optionKey | cmdKey)
        let registerStatus = RegisterEventHotKey(UInt32(kVK_ANSI_K), modifiers, hotKeyID,
                                                 GetApplicationEventTarget(), 0, &hotKeyRef)
        guard registerStatus == 0 else {
            Log.app.error("RegisterEventHotKey failed: \(registerStatus, privacy: .public)")
            return false
        }
        return true
    }

    func unregister() {
        if let hotKeyRef { UnregisterEventHotKey(hotKeyRef) }
        hotKeyRef = nil
        if let handlerRef { RemoveEventHandler(handlerRef) }
        handlerRef = nil
    }

    private func fire() {
        guard let action else { return }
        // Carbon delivers hot keys on the main thread; hop explicitly anyway.
        onMain {
            action()
        }
    }

    deinit {
        unregister()
    }
}
