# Test IDs (`data-testid`) — browser client

Stable hooks for Playwright e2e tests. Select with `page.getByTestId("…")`
(Playwright's default attribute is `data-testid`). Names are stable; visible
text is not (it may be reworded for the owner). If you rename one, update this
file and the e2e tests in the same change.

Names requested in the original brief that map to a different (kept-stable)
id: `toolbar` → `session-toolbar`; `fullscreen-button` → `toolbar-fullscreen`;
`display-select` → `toolbar-display`; `quality-select` → `toolbar-quality`;
`mute-button` → `toolbar-audio`; `keyboard-button` → `toolbar-keyboard`;
`help-button` → `toolbar-help`. `home-status-text` exists (wrapper of
`home-status-title` + `home-status-detail`).

Conventions

- Every view is wrapped in `view-<name>` (also mirrored as
  `document.body.dataset.view` / `#app[data-view]`): `view-first-run`,
  `view-setup`, `view-login`, `view-link`, `view-pair`, `view-home`,
  `view-loading`, `view-error`, `view-not-set-up`, `view-revoked`,
  `view-missing-pin`, `view-unsupported`. The session view is `session-view`
  (no page chrome).
- Every view shows at most one `error-message` (role=alert, `hidden` when
  empty). Its `data-scope` attribute says which form it belongs to
  (`firstrun`, `setup`, `login`, `link`, `pair`, `error-view`).
- Confirmation dialogs: the `<dialog>` has a specific id (e.g. `block-confirm`,
  `device-remove-confirm`); its buttons are always `confirm-ok` and
  `confirm-cancel` (only one confirmation is open at a time). The dialog is
  in the DOM as soon as the triggering click returns.
  Every sheet/dialog has a close button `<id>-close`.
- Toasts: container `toasts`, each message `toast` (`data-level`
  = `info` | `error` | `success`).
- Async buttons get `aria-busy="true"` while working; disabled buttons have
  the `disabled` property.

## First run (Tauri app only, no server configured)

| testid | element |
|---|---|
| `firstrun-origin-input` | server address text input |
| `firstrun-save` | "Continue" (submit) |
| `error-message` (`data-scope=firstrun`) | validation / probe error |

## Setup (`/#setup=…` from the Mac's QR code; fragment is stripped at load)

| testid | element |
|---|---|
| `setup-card` | card |
| `setup-status` | live status line ("Checking with your Mac…", "Waiting for your Mac to confirm…") |
| `setup-device-name` | device name input |
| `setup-create-passkey` | "Create passkey" (starts WebAuthn create) |
| `setup-retry` | "Try again" |
| `setup-continue` | "Continue" (after a timeout / error) |
| `setup-done` | success check mark (device approved) |
| `setup-mac-fingerprint` | Mac key fingerprint line |
| `error-message` (`data-scope=setup`) | error |

## Login

| testid | element |
|---|---|
| `login-card` | card |
| `login-button` | browser: "Sign in with passkey"; Tauri: "Sign in" (starts the link flow) |
| `error-message` (`data-scope=login`) | error |
| `link-code` | Tauri only: the 8-character code to type in a browser (`ABCD-EFGH`) |
| `link-status` | Tauri only: "Waiting for you to enter the code…" |
| `link-open-browser` | Tauri only: "Open browser again" |
| `link-cancel` | cancel |
| `change-server` | Tauri only: "Change server address" |

## Approve an app sign-in (`/#link`, signed in with a passkey)

| testid | element |
|---|---|
| `link-card` | card |
| `link-warning` | "only enter a code shown on your own computer" note |
| `link-code-input` | code input (auto-formats to `ABCD-EFGH`) |
| `link-approve-button` | "Approve sign-in" (submit) |
| `link-done` | success check mark |
| `link-home` | "Back to Home" |
| `link-cancel` | cancel |
| `error-message` (`data-scope=link`) | error |

## Pairing (signed in, device not yet approved)

| testid | element |
|---|---|
| `pair-card` | card |
| `pair-host-status` | "Your Mac is offline…" line (empty when online) |
| `pair-name-input` | device name input |
| `pair-start-button` | "Ask for approval" |
| `pair-status` | status line ("Contacting your Mac…", "Waiting for approval…") |
| `pair-sas` | the big 6-digit code, formatted `123 456`; `data-sas="123456"` |
| `pair-cancel` | cancel |
| `pair-retry` | "Try again" (after denial / timeout) |
| `pair-approved` | success check mark |
| `pair-forget-host` | "I reinstalled my Mac — trust the new one" (pin mismatch) |
| `pair-forget-confirm` | its confirmation dialog (`confirm-ok` / `confirm-cancel`) |
| `error-message` (`data-scope=pair`) | error |
| `signout-button` | "Sign out" |

## Home (approved device)

| testid | element |
|---|---|
| `home-status` | big status card; `data-state` = `online` \| `offline` \| `busy` (someone connected) \| `blocked` \| `checking` \| `warning` (host key mismatch) |
| `home-status-title` | status title (h1): "Online" / "Offline" / "Someone connected" / "Blocked" / "Checking…" / "Security warning" |
| `home-status-detail` | one-line explanation |
| `home-status-text` | wrapper around title + detail |
| `home-mac-name` | Mac name |
| `offline-help` | "Why offline?" (opens `offline-help-sheet`) |
| `connect-button` | "Connect" (enabled when `online` or `busy`) |
| `host-mismatch` | security warning box; `host-mismatch-reset` → `host-mismatch-confirm` dialog (`confirm-ok`) |
| `approvals` | "Approval needed" card (`hidden` when empty) |
| `approval-item` | one request; `data-request-id` (b64), `data-state` = `open` \| `sending` \| `sent` \| `invalid` |
| `approval-name` / `approval-kind` | requested name / kind |
| `approval-sas` | 6-digit code to compare, `data-sas="123456"` (absent when the request failed verification) |
| `approval-approve` | "Approve" (signs HR1/pair-approve) |
| `approval-deny` | "Deny" |
| `approval-error` | verification failure text (only Deny is offered then) |
| `approval-sent` | "Approved. Waiting for your Mac to confirm…" |
| `controls` | Security card |
| `block-button` | "Block all connections" → `block-confirm` dialog (`confirm-ok`) → signed HR1/kill-request `kill` |
| `allow-button` | "Allow connections" (shown instead of block when `data-state=blocked`) → HR1/kill-request `resume` |
| `devices-list` | trusted devices list |
| `device-item` | one device; `data-pub` (b64), `data-status`, `data-mine="1"` for this device |
| `device-name` | its name |
| `device-remove` | "Remove" → `device-remove-confirm` dialog (`confirm-ok`) → signed HR1/revoke-request |
| `passkeys-list` | passkeys list |
| `passkey-item` | one passkey; `data-id` |
| `passkey-remove` | "Remove" (only when more than one) → `passkey-remove-confirm` (`confirm-ok`) |
| `passkey-add` | "Add a passkey" (browser only) → `passkey-sheet` → `passkey-create` |
| `mac-fingerprint` / `device-fingerprint` | footer key fingerprints |
| `signout-button` | "Sign out" |

## Session (`/#session`)

| testid | element |
|---|---|
| `session-view` | root; `data-stage` = `requesting` \| `negotiating` \| `connecting` \| `connected` \| `ended` |
| `session-video` | the `<video>` |
| `session-surface` | transparent input surface over the video (focus it, then type / click) |
| `session-overlay` | connecting / ended overlay (`hidden` while connected) |
| `session-status` | overlay title, in both the connecting and the ended card; `data-stage` as above (e.g. "Asking your Mac…", "Securing the connection…", "Connecting…", "Session ended") |
| `session-cancel` | "Cancel" while connecting |
| `session-ended` | ended card; `data-kind` = `user` \| `host` \| `rejected` \| `security` \| `error` |
| `session-end-reason` | plain-language reason |
| `session-auto-reconnect` | "Reconnecting automatically…" (shown after a live session dropped; up to 3 tries) |
| `reconnect-button` | "Reconnect" |
| `session-home` | "Back to Home" |
| `session-unmute` | "Turn on sound" (when autoplay with sound was blocked) |
| `latency-pill` | pill; `data-level` = `good` (< 40 ms) \| `ok` (< 100 ms) \| `bad` \| `unknown`, `data-route` = `direct` \| `relay` |
| `latency-rtt` / `latency-fps` / `latency-mbps` / `latency-route` | pill parts ("23 ms", "60 fps", "12 Mbps", "Direct"/"Relay") |
| `session-toolbar` | toolbar (`role=toolbar`; auto-hides by sliding off-screen — hover/focus it, move the pointer to the top edge, or press `toolbar-handle`) |
| `toolbar-handle` | small handle that reveals the toolbar |
| `toolbar-fullscreen` | full screen + keyboard lock; `aria-pressed` (hidden if the Fullscreen API is unavailable) |
| `toolbar-display` | display picker (disabled with < 2 displays) → `display-menu` → `display-option` (`data-value` = display id, `aria-checked`) |
| `toolbar-quality` | quality → `quality-menu` → `quality-option` (`data-value` = `auto` \| `sharp` \| `smooth`, `aria-checked`) |
| `toolbar-audio` | sound on/off (mute); `data-muted` = `true` \| `false`, `aria-pressed` = sound on |
| `toolbar-clipboard` | opens `clipboard-menu`; `aria-pressed` = sync on |
| `clipboard-toggle` | (in `clipboard-menu`) automatic clipboard sync on/off, `aria-checked` |
| `clipboard-send` | (in `clipboard-menu`) send my clipboard to the Mac now |
| `files-button` | opens `files-panel`; badge `files-badge` = active transfers |
| `toolbar-ctrlcmd` | "Use Ctrl as ⌘"; `aria-pressed` |
| `toolbar-keyboard` | on-screen keyboard (focuses `keyboard-input`) |
| `keyboard-input` | hidden textarea that receives on-screen-keyboard text |
| `toolbar-help` | opens `help-sheet` (rows `help-shortcut`) |
| `disconnect-button` | disconnect |
| `dropzone` | drag-and-drop overlay |
| `upload-input` | hidden `<input type=file multiple>` — use `setInputFiles()` |

### Files panel (`files-panel`, a side sheet)

| testid | element |
|---|---|
| `upload-button` | "Choose files…" (clicks `upload-input`) |
| `transfers-list` | transfers |
| `transfer-item` | one transfer; `data-dir` = `up` \| `down`, `data-state` = `hashing` \| `waiting` \| `sending` \| `receiving` \| `verifying` \| `done` \| `error` \| `cancelled`, `data-name` |
| `transfer-name` / `transfer-state` | name / state text |
| `transfer-cancel` | cancel an active transfer |
| `transfers-clear` | "Clear finished" |
| `files-path` | current folder ("Home / Projects") |
| `files-up` / `files-refresh` | up one folder / refresh |
| `files-list` | entries of the Mac home folder |
| `file-entry` | one entry; `data-name`, `data-dir` = `1` \| `0`. A folder row is itself clickable (`role=button`, Enter/Space) |
| `folder-open` | open a folder entry |
| `download-button` | download a file entry (saved via a `blob:` download) |
| `files-panel-close` | close the panel |

## Other screens

| testid | element |
|---|---|
| `loading` | loading spinner block |
| `error-card` / `error-message` (`data-scope=error-view`) / `error-retry` / `error-change-server` | generic error screen |
| `not-set-up` / `not-set-up-retry` | server not claimed yet |
| `revoked` / `revoked-pair-again` | this device was removed |
| `missing-pin` / `missing-pin-pair-again` / `missing-pin-confirm` | approved but no pinned Mac key |
| `unsupported` | browser lacks Ed25519 / WebAuthn / secure context |
