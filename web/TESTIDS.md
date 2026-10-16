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
  `view-add-mac`, `view-join-needs-approval`, `view-loading`, `view-error`,
  `view-not-set-up`, `view-revoked`, `view-missing-pin`, `view-unsupported`. The session view is `session-view`
  (no page chrome).
- Every view shows at most one `error-message` (role=alert, `hidden` when
  empty). Its `data-scope` attribute says which form it belongs to
  (`firstrun`, `setup`, `login`, `link`, `pair`, `add-mac`, `error-view`).
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

## Pairing — "Ask for access" to one Mac (signed in, not yet approved on that Mac)

Shown directly after sign-in when the account has one Mac and this device is
approved on none; otherwise reached with `mac-ask-access` on a Mac card.

| testid | element |
|---|---|
| `pair-card` | card |
| `pair-mac` | which Mac is being asked: `pair-mac-name` + `pair-mac-id` ("Mac ID 482 913 557") |
| `pair-host-status` | "“Studio Mac” is offline…" line (empty when online) |
| `pair-name-input` | device name input (pre-filled with the registered name if any) |
| `pair-start-button` | "Ask for approval" (pair-start carries that Mac's hostPub) |
| `pair-status` | status line ("Contacting “Studio Mac”…", "Waiting for approval…") |
| `pair-sas` | the big 6-digit code, formatted `123 456`; `data-sas="123456"` |
| `pair-cancel` | cancel |
| `pair-retry` | "Try again" (after denial / timeout) |
| `pair-back` | "Back to my Macs" (only when there are other Macs / an approved Mac) |
| `pair-approved` | success check mark |
| `error-message` (`data-scope=pair`) | error (a challenge from a different Mac than the one asked is a security warning) |
| `signout-button` | "Sign out" |

## Home — "Your Macs" (signed in)

Approved on at least one Mac → full home. Approved on none and the account has
several Macs → the same page with only the Mac cards (each offering "Ask for
access"), `macs-intro`, and no devices / passkeys / add-Mac.

| testid | element |
|---|---|
| `macs-heading` | "Your Macs" h1 (`hidden` with a single Mac — then the card's status title is the h1) |
| `macs-intro` | "Choose a Mac to ask for access…" (only when this device is approved on no Mac) |
| `macs-list` | list of Mac cards (always present, also with one Mac); `macs-empty` when the account has none |
| `mac-card` | one Mac. `data-host-pub` (b64 key), `data-mac-id` (9 digits, computed locally from the key), `data-state` = `online` \| `offline` \| `busy` (someone connected) \| `blocked` \| `checking`, `data-device-status` = this device on that Mac: `approved` \| `pending` \| `revoked` \| `unknown` |
| `mac-name` | Mac name |
| `mac-id` | Mac ID, formatted `482 913 557` |
| `mac-status-title` | big status: "Online" / "Offline" / "Someone connected" / "Blocked" / "Checking…" |
| `mac-status-detail` | one line ("Ready to connect.", "Studio Laptop is using this Mac.", …) |
| `mac-note` | this device's approval on that Mac when not usable ("isn't approved on this Mac yet", "waiting for approval", "was removed", "can't verify this Mac's key") |
| `offline-help` | "Why offline?" (on offline cards; opens `offline-help-sheet`) |
| `mac-connect` | "Connect" — only when this device is approved on that Mac AND has its key pinned; enabled when `online` or `busy` |
| `mac-ask-access` | "Ask for access" — when not approved on that Mac (opens the pairing view for it); disabled while the Mac is offline |
| `mac-block` | "Block all connections" (approved cards) → `block-confirm` (`confirm-ok`) → signed kill-request `kill` with that hostPub |
| `mac-allow` | "Allow connections" (instead of Connect/Block while `data-state=blocked`) → kill-request `resume` |
| `mac-menu` | "…" details → `mac-menu-sheet`: `mac-menu-mac-id`, `mac-menu-device-status`, `mac-fingerprint` (pinned key fingerprint, or "Not verified on this device") |
| `mac-remove` | (in `mac-menu-sheet`, approved devices only) "Remove this Mac from my account" → `mac-remove-confirm` (`confirm-ok`) → POST /api/hosts/remove |
| `add-mac-button` | "Add a Mac" (approved devices only) → Add-a-Mac view |
| `approvals` | "Approval needed" card (`hidden` when empty; shown above the Macs) |
| `approval-item` | one request; `data-request-id` (b64), `data-host-pub` (the Mac it is for), `data-state` = `open` \| `sending` \| `sent` \| `invalid` |
| `approval-name` / `approval-kind` | requested name / "Web browser wants to use “Studio Mac”" |
| `approval-mac` | the Mac it is for: "Mac ID 482 913 557" |
| `approval-sas` | 6-digit code to compare, `data-sas="123456"` (absent when the request failed verification with THAT Mac's pinned key) |
| `approval-approve` | "Approve" (signs HR1/pair-approve for that Mac) |
| `approval-deny` | "Deny" |
| `approval-error` | verification failure text (only Deny is offered then) |
| `approval-sent` | "Approved. Waiting for “Studio Mac” to confirm…" |
| `devices-list` | trusted devices list (approved devices only) |
| `device-item` | one device; `data-pub` (b64), `data-status` (`approved` on any Mac \| `pending` \| `unknown`), `data-mine="1"` for this device |
| `device-name` | its name |
| `device-macs` / `device-mac-chip` | chips with the Macs it is approved on (`data-host-pub`; `data-pending="1"` = waiting); hidden with a single Mac |
| `device-remove` | "Remove" → `device-remove-confirm` (`confirm-ok`) → a signed revoke-request to every Mac it is approved on that this device can sign for (disabled if none) |
| `passkeys-list` / `passkey-item` (`data-id`) / `passkey-remove` (→ `passkey-remove-confirm`) / `passkey-add` (→ `passkey-sheet` → `passkey-create`) | passkeys (approved devices only) |
| `device-fingerprint` | footer: this device's key fingerprint |
| `signout-button` | "Sign out" |

Single-Mac compatibility ids, **on the first card only** (they used to be the
single status card). They sit on inner elements so the card's own ids stay on
the real controls: `home-status` (the card's status block, with the same
`data-state`), `home-status-text` (wrapper of the title + detail),
`home-status-title` (span inside `mac-status-title`), and `connect-button` /
`block-button` / `allow-button` (the label span inside `mac-connect` /
`mac-block` / `mac-allow`; the button also gets `aria-disabled="true"` when
disabled, so tools treat the label as disabled too). Prefer the `mac-*` ids in
new tests. Removed with multiple Macs: `controls` (Block/Allow moved onto each
card), `home-mac-name` (→ `mac-name`), `home-status-detail` (→
`mac-status-detail`), `host-mismatch`, `host-mismatch-reset`,
`host-mismatch-confirm`, `pair-forget-host`, `pair-forget-confirm` (a
reinstalled Mac has a new key, so it is simply a new Mac to add; the old entry
can be removed). The footer `mac-fingerprint` moved into `mac-menu-sheet`.

## Add a Mac (`add-mac-button`, or the new Mac's QR link `/#join=…`; the fragment is stripped at load)

| testid | element |
|---|---|
| `add-mac-card` | card |
| `add-mac-status` | live status line ("Looking for your Mac…", "Adding “Studio Mac”…", "Waiting for the Mac to confirm…") |
| `add-mac-id-input` | Mac ID (9 digits; spaces/dashes allowed, auto-formats to `482 913 557`) |
| `add-mac-code-input` | code (case-insensitive, spaces/dashes allowed, 0→O 1→I 8→B; auto-formats to `ABCD-EFGH-IJKL-MNOP`) |
| `add-mac-submit` | typed path: "Add Mac" (submit). QR path: "Add this Mac" on the confirmation |
| `add-mac-confirm` | QR path only: confirmation box with `add-mac-name` and `add-mac-mac-id` ("Mac ID 482 913 557"). **A link alone never adds a Mac** — the owner taps `add-mac-submit` |
| `add-mac-done` | success check mark (cert AND hostMac verified, key pinned) |
| `add-mac-home` | "Done" → Home |
| `add-mac-retry` | "Try again" after an error (back to the typed form, Mac ID kept) |
| `add-mac-cancel` | cancel → Home |
| `error-message` (`data-scope=add-mac`) | error |
| `join-needs-approval` / `join-needs-approval-continue` | a join link opened on a device approved on no Mac |
| `login-join-hint` | on the sign-in card while a join link waits for sign-in |

## Session (`/#session`)

| testid | element |
|---|---|
| `session-view` | root; `data-stage` = `requesting` \| `negotiating` \| `connecting` \| `connected` \| `ended` |
| `session-video` | the `<video>` |
| `session-surface` | transparent input surface over the video (focus it, then type / click) |
| `session-overlay` | connecting / ended overlay (`hidden` while connected) |
| `session-status` | overlay title, in both the connecting and the ended card; `data-stage` as above (e.g. "Asking the Mac…", "Securing the connection…", "Connecting…", "Session ended") |
| `session-mac-name` | name of the Mac this session is for (in the connecting and the ended card) |
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
| `toolbar-mac-name` | name of the connected Mac (first item of the toolbar) |
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
