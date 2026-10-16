import AppKit
import HRCore
import SwiftUI

/// The icon in the menu bar; its shape reflects the status.
struct MenuBarLabel: View {
    @ObservedObject var model: AppModel

    var body: some View {
        let summary = model.summary
        Image(systemName: summary.kind.menuBarSymbol)
            .accessibilityLabel(Text("Heartfulness Remote: \(summary.title)"))
    }
}

/// The window that drops down from the menu bar icon.
struct MenuBarPanel: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            StatusHeader(summary: model.summary)

            if let session = model.state.session {
                SessionControls(session: session) {
                    model.disconnectNow()
                }
            }

            if model.agentRunning || model.connectionsBlocked {
                BlockConnectionsToggle()
            }

            if !model.state.pending.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    Label("Waiting for your approval", systemImage: "checkmark.shield")
                        .font(.subheadline.weight(.semibold))
                    ForEach(model.state.pending) { request in
                        ApprovalCard(request: request, compact: true)
                    }
                    Text("Approve only if the code matches the one on that device.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if model.state.server == .online && !model.state.claimed && model.agentRunning {
                Button {
                    model.openSetup(steps: [.pairPhone])
                } label: {
                    Label("Pair your phone…", systemImage: "qrcode")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }

            Divider()

            VStack(alignment: .leading, spacing: 2) {
                PanelRowButton(title: "Open Dashboard…", systemImage: "macwindow") {
                    WindowManager.shared.showDashboard()
                }
                if !model.settings.setupCompleted {
                    PanelRowButton(title: "Continue Setup…", systemImage: "sparkles") {
                        model.openSetup()
                    }
                }
                PanelRowButton(title: "Quit Heartfulness Remote", systemImage: "power") {
                    NSApp.terminate(nil)
                }
            }
        }
        .padding(14)
        .frame(width: 340)
    }
}
