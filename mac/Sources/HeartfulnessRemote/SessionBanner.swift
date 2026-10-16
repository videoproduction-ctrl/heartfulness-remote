import AppKit
import SwiftUI

/// The always-visible "being controlled" banner: one borderless, non-activating panel per
/// screen, above everything (including full-screen apps), with "Disconnect" and "Block All"
/// (kill switch) buttons.
/// It is excluded from the stream because the capture filter excludes this app.
@MainActor
final class SessionBanner {
    private var panels: [NSPanel] = []
    private var deviceName: String?
    private var onDisconnect: (() -> Void)?
    private var onBlock: (() -> Void)?
    private var screenObserver: NSObjectProtocol?

    var isVisible: Bool { deviceName != nil }

    func show(deviceName: String, onDisconnect: @escaping () -> Void, onBlock: @escaping () -> Void) {
        if self.deviceName == deviceName && !panels.isEmpty { return }
        self.deviceName = deviceName
        self.onDisconnect = onDisconnect
        self.onBlock = onBlock
        rebuild()
        if screenObserver == nil {
            screenObserver = NotificationCenter.default.addObserver(
                forName: NSApplication.didChangeScreenParametersNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.rebuild()
                }
            }
        }
    }

    func hide() {
        deviceName = nil
        onDisconnect = nil
        onBlock = nil
        for panel in panels { panel.orderOut(nil) }
        panels.removeAll()
        if let screenObserver {
            NotificationCenter.default.removeObserver(screenObserver)
            self.screenObserver = nil
        }
    }

    private func rebuild() {
        for panel in panels { panel.orderOut(nil) }
        panels.removeAll()
        guard let name = deviceName else { return }
        for screen in NSScreen.screens {
            panels.append(makePanel(on: screen, deviceName: name))
        }
    }

    private func makePanel(on screen: NSScreen, deviceName: String) -> NSPanel {
        let content = SessionBannerView(deviceName: deviceName,
                                        onDisconnect: { [weak self] in self?.onDisconnect?() },
                                        onBlock: { [weak self] in self?.onBlock?() })
        let hosting = NSHostingView(rootView: content)
        let fitting = hosting.fittingSize
        let width = min(max(fitting.width, 360), screen.visibleFrame.width - 40)
        let height = max(fitting.height, 44)
        let visible = screen.visibleFrame
        let frame = NSRect(x: visible.midX - width / 2, y: visible.maxY - height - 8, width: width, height: height)

        let panel = NSPanel(contentRect: frame,
                            styleMask: [.borderless, .nonactivatingPanel],
                            backing: .buffered,
                            defer: false)
        panel.level = .screenSaver
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.becomesKeyOnlyIfNeeded = true
        panel.isMovableByWindowBackground = true
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.isReleasedWhenClosed = false
        panel.title = "Heartfulness Remote session"
        hosting.frame = NSRect(origin: .zero, size: frame.size)
        hosting.autoresizingMask = [.width, .height]
        panel.contentView = hosting
        panel.setFrame(frame, display: true)
        panel.orderFrontRegardless()
        return panel
    }
}

@MainActor
struct SessionBannerView: View {
    let deviceName: String
    let onDisconnect: () -> Void
    let onBlock: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "person.crop.circle.badge.exclamationmark")
                .font(.system(size: 18, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
            Text("● \(deviceName) is controlling this Mac")
                .font(.system(size: 14, weight: .semibold))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 12)
            Button(action: onDisconnect) {
                Label("Disconnect", systemImage: "xmark.circle.fill")
                    .font(.system(size: 13, weight: .semibold))
            }
            .buttonStyle(.borderedProminent)
            .tint(.white.opacity(0.25))
            .controlSize(.regular)
            .accessibilityHint("Ends the remote session immediately")
            Button(action: onBlock) {
                Label("Block All", systemImage: "hand.raised.fill")
                    .font(.system(size: 13, weight: .semibold))
            }
            .buttonStyle(.borderedProminent)
            .tint(.white.opacity(0.25))
            .controlSize(.regular)
            .help("Disconnect and refuse every connection until you allow them again (⌃⌥⌘K)")
            .accessibilityHint("Disconnects and blocks all connections until you allow them again")
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .frame(minWidth: 360)
        .background(
            Capsule(style: .continuous)
                .fill(LinearGradient(colors: [Color(red: 1.0, green: 0.45, blue: 0.0), Color(red: 0.9, green: 0.15, blue: 0.1)],
                                     startPoint: .leading, endPoint: .trailing))
        )
        .overlay(
            Capsule(style: .continuous).strokeBorder(.white.opacity(0.35), lineWidth: 1)
        )
        .padding(2)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(deviceName) is controlling this Mac")
    }
}
