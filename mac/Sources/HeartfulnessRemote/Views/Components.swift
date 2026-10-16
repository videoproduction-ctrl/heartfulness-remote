import AppKit
import HRCore
import SwiftUI

// MARK: - Status styling

extension HostStatusSummary.Kind {
    /// Symbol in the menu panel and dashboard (SF Symbols, multicolour via tint).
    var symbol: String {
        switch self {
        case .online: return "checkmark.circle.fill"
        case .offline: return "wifi.slash"
        case .connected: return "person.crop.circle.badge.exclamationmark"
        case .blocked: return "hand.raised.fill"
        case .attention: return "exclamationmark.triangle.fill"
        }
    }

    /// Template symbol in the menu bar (monochrome, so the shape alone tells the status).
    var menuBarSymbol: String {
        switch self {
        case .online: return "display"
        case .offline: return "wifi.slash"
        case .connected: return "person.crop.circle.badge.exclamationmark"
        case .blocked: return "hand.raised.fill"
        case .attention: return "exclamationmark.triangle.fill"
        }
    }

    var color: Color {
        switch self {
        case .online: return .green
        case .offline: return .gray
        case .connected: return .orange
        case .blocked: return .red
        case .attention: return .red
        }
    }
}

enum DeviceStyle {
    static func symbol(kind: String, name: String) -> String {
        let n = name.lowercased()
        if n.contains("iphone") || n.contains("android") || n.contains("phone") || n.contains("pixel") { return "iphone" }
        if n.contains("ipad") || n.contains("tablet") { return "ipad" }
        if DeviceKindText.isBrowser(kind) { return "globe" }
        if n.contains("macbook") || n.contains("laptop") { return "laptopcomputer" }
        return "desktopcomputer"
    }
}

// MARK: - Big status

struct StatusHeader: View {
    enum Size {
        case compact
        case large
    }

    let summary: HostStatusSummary
    var size: Size = .compact

    var body: some View {
        HStack(alignment: .center, spacing: size == .large ? 18 : 12) {
            Image(systemName: summary.kind.symbol)
                .font(.system(size: size == .large ? 54 : 32, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(summary.kind.color)
                .frame(width: size == .large ? 72 : 44, height: size == .large ? 72 : 44)
            VStack(alignment: .leading, spacing: 3) {
                Text(summary.title)
                    .font(size == .large ? Font.system(size: 26, weight: .bold) : Font.system(size: 15, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(summary.detail)
                    .font(size == .large ? Font.body : Font.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }
}

/// "Mac ID 482 913 557" under the big status. The owner reads it out or types it on another
/// device to find this Mac; it is not a secret.
struct MacIDLabel: View {
    let line: String
    var large = false

    var body: some View {
        Label {
            Text(line)
                .monospacedDigit()
                .textSelection(.enabled)
        } icon: {
            Image(systemName: "desktopcomputer")
        }
        .font(large ? Font.title3.weight(.semibold) : Font.callout.weight(.semibold))
        .foregroundStyle(.secondary)
    }
}

/// Numbered instructions (1. 2. 3.).
struct NumberedSteps: View {
    let items: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(items.enumerated()), id: \.offset) { item in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(item.offset + 1).")
                        .font(.body.weight(.semibold))
                        .monospacedDigit()
                    Text(item.element)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

/// "Add this Mac to your account" (PROTOCOL.md §10.2): a QR code for a phone that is already
/// signed in, plus the typed alternative — Mac ID and one-time code — for any other device.
struct JoinMacPanel: View {
    let qrImage: NSImage
    /// Formatted, e.g. "482 913 557".
    let macID: String
    /// Formatted by the agent, e.g. "K7QP-3MZD-WX2R-9TFA".
    let joinCode: String
    var qrSize: CGFloat = 190

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 22) {
                Image(nsImage: qrImage)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: qrSize, height: qrSize)
                    .padding(12)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .accessibilityLabel(Text("Code for adding this Mac to your account"))
                NumberedSteps(items: AccountText.scanSteps)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            VStack(alignment: .leading, spacing: 12) {
                Text(AccountText.typeInstead)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(alignment: .top, spacing: 32) {
                    JoinValue(caption: "Mac ID", value: macID, selectable: true)
                    // The code is a one-time secret: shown for typing, not selectable or copyable.
                    JoinValue(caption: "Code", value: joinCode, selectable: false)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            Label(AccountText.codePrivacy, systemImage: "lock.fill")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A caption above a large monospaced value ("Mac ID" / "482 913 557").
private struct JoinValue: View {
    let caption: String
    let value: String
    let selectable: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(caption)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            if selectable {
                valueText.textSelection(.enabled)
            } else {
                valueText
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var valueText: some View {
        Text(value)
            .font(.system(size: 26, weight: .bold, design: .monospaced))
            .lineLimit(1)
            .minimumScaleFactor(0.6)
    }
}

/// "Connected for 12:34 · Direct connection · 18 ms" + Disconnect button.
struct SessionControls: View {
    let session: SessionInfo
    let onDisconnect: () -> Void
    var large = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "clock")
                    .foregroundStyle(.secondary)
                if let since = session.since?.date {
                    Text("Connected for")
                    Text(since, style: .timer)
                        .monospacedDigit()
                } else {
                    Text("Connected")
                }
            }
            .font(large ? Font.body : Font.callout)
            let line = SessionText.connectionLine(session)
            if !line.isEmpty {
                Text(line)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button(role: .destructive, action: onDisconnect) {
                Label("Disconnect now", systemImage: "xmark.circle.fill")
                    .frame(maxWidth: large ? nil : CGFloat.infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .controlSize(.large)
        }
    }
}

/// Kill switch row bound to `model.connectionsBlocked`.
struct BlockConnectionsToggle: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Toggle(isOn: $model.connectionsBlocked) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Block all connections")
                    .font(.body.weight(.medium))
                Text(model.connectionsBlocked
                     ? "Nobody can connect. Switch off to allow approved devices again."
                     : "Instantly stops and refuses every session. Shortcut: ⌃⌥⌘K")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .toggleStyle(.switch)
        .tint(.red)
    }
}

// MARK: - Approvals

/// "123 456" in large monospaced digits.
struct SASCodeText: View {
    let code: String
    var fontSize: CGFloat = 40

    var body: some View {
        Text(SASFormatter.format(code))
            .font(.system(size: fontSize, weight: .bold, design: .monospaced))
            .textSelection(.enabled)
            .accessibilityLabel(Text("Code \(code)"))
    }
}

struct ApprovalCard: View {
    @EnvironmentObject var model: AppModel
    let request: PendingApproval
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 8 : 14) {
            HStack(spacing: 10) {
                Image(systemName: DeviceStyle.symbol(kind: request.kind, name: request.name))
                    .font(.system(size: compact ? 20 : 28))
                    .foregroundStyle(.blue)
                    .frame(width: compact ? 26 : 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(request.displayName)
                        .font(compact ? Font.headline : Font.title3.weight(.semibold))
                    Text(DeviceKindText.label(request.kind) + " wants to control this Mac")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Code on that device should be:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                SASCodeText(code: request.sas, fontSize: compact ? 28 : 44)
            }
            if !compact {
                Label("Only approve if this code is exactly the same as the code shown on the device you are adding. If you aren't adding a device right now, click Deny.",
                      systemImage: "exclamationmark.shield")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let expires = request.expiresAt?.date, expires > Date() {
                HStack(spacing: 4) {
                    Text("Expires in")
                    Text(expires, style: .timer)
                        .monospacedDigit()
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            HStack(spacing: 10) {
                Button(role: .destructive) {
                    model.deny(request)
                } label: {
                    Text("Deny")
                        .frame(minWidth: compact ? 60 : 90)
                }
                .buttonStyle(.bordered)
                .controlSize(compact ? .regular : .large)
                Button {
                    model.approve(request)
                } label: {
                    Text("Approve")
                        .frame(minWidth: compact ? 60 : 90)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .controlSize(compact ? .regular : .large)
            }
        }
        .padding(compact ? 10 : 18)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

// MARK: - Small pieces

/// A coloured "Allowed ✓ / Not allowed" capsule.
struct StatusPill: View {
    let ok: Bool?
    var okText = "On"
    var badText = "Off"
    var unknownText = "Unknown"

    var body: some View {
        let text = ok == true ? okText : (ok == false ? badText : unknownText)
        let color: Color = ok == true ? .green : (ok == false ? .orange : .gray)
        HStack(spacing: 4) {
            Image(systemName: ok == true ? "checkmark.circle.fill" : (ok == false ? "exclamationmark.circle.fill" : "questionmark.circle"))
            Text(text)
        }
        .font(.callout.weight(.medium))
        .foregroundStyle(color)
    }
}

/// A red/orange box for problems, with optional buttons.
struct ProblemBox<Actions: View>: View {
    let title: String
    let message: String
    var color: Color = .red
    @ViewBuilder var actions: () -> Actions

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(color)
            Text(message)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                actions()
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(color.opacity(0.35), lineWidth: 1))
    }
}

/// Full-width menu-style row with a hover highlight (for the menu bar panel).
struct PanelRowButton: View {
    let title: String
    let systemImage: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(hovering ? Color.accentColor.opacity(0.18) : Color.clear,
                    in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        .onHover { hovering = $0 }
    }
}
