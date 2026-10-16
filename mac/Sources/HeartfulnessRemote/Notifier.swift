import Foundation
import UserNotifications

/// User notifications (session started, new device asking to pair, idle warning, …).
final class Notifier: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    static let pairCategory = "HR_PAIR_REQUEST"
    static let openApprovalsAction = "HR_OPEN_APPROVALS"

    /// Called on the main thread when the owner clicks a notification.
    /// Argument: true if it was about a pairing request.
    var onOpen: (@Sendable (Bool) -> Void)?

    /// UNUserNotificationCenter crashes outside an .app bundle (e.g. `swift run`).
    private var isAvailable: Bool {
        Bundle.main.bundleURL.pathExtension == "app" && Bundle.main.bundleIdentifier != nil
    }

    func setUp() {
        guard isAvailable else { return }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let open = UNNotificationAction(identifier: Notifier.openApprovalsAction, title: "Open Approvals", options: [.foreground])
        let pairing = UNNotificationCategory(identifier: Notifier.pairCategory, actions: [open], intentIdentifiers: [], options: [])
        center.setNotificationCategories([pairing])
    }

    func requestAuthorization(_ completion: @escaping @Sendable (Bool) -> Void) {
        guard isAvailable else {
            completion(false)
            return
        }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            completion(granted)
        }
    }

    /// nil = unknown/not determined, otherwise whether notifications are allowed.
    func authorizationStatus(_ completion: @escaping @Sendable (Bool?) -> Void) {
        guard isAvailable else {
            completion(nil)
            return
        }
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .authorized, .provisional:
                completion(true)
            case .denied:
                completion(false)
            default:
                completion(nil)
            }
        }
    }

    func post(title: String, body: String, identifier: String = UUID().uuidString, category: String? = nil) {
        guard isAvailable else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        if let category { content.categoryIdentifier = category }
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                Log.app.error("Notification failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    // MARK: UNUserNotificationCenterDelegate

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // Show banners even while the dashboard is in front: these are security notices.
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let isPairing = response.notification.request.content.categoryIdentifier == Notifier.pairCategory
            || response.actionIdentifier == Notifier.openApprovalsAction
        let handler = onOpen
        DispatchQueue.main.async {
            handler?(isPairing)
        }
        completionHandler()
    }
}
