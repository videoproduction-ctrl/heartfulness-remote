# Heartfulness Remote — User Guide

Heartfulness Remote lets you use your Mac from anywhere — see the screen, hear
its sound, use the mouse and keyboard, copy and paste, and move files — from a
web browser or the Heartfulness Remote app on another computer. It belongs
to you: it runs on your own Mac and your own small server, and only devices you
have approved can connect.

---

## 1. What's what

| Piece | Where it lives | What it does |
|---|---|---|
| **Heartfulness Remote** (Mac app) | Your Mac, in the menu bar (top right) | Shares your Mac's screen and lets approved devices control it |
| **Your web address** | e.g. `https://heartfulness-remote.duckdns.org` | Open it in any browser to connect — nothing to install |
| **Heartfulness Remote** (desktop app) | Optional, on other Macs or Windows PCs | The same thing as the web page, as an app |
| **Your phone** | Your pocket | Signs you in (passkey) and approves new devices |

**Status you'll see everywhere:**

| Status | Meaning |
|---|---|
| 🟢 **Online** | Your Mac is ready. You can connect. |
| ⚪ **Offline** | Your Mac isn't reachable right now (see section 8). |
| 🟠 **Someone connected** | A device is using your Mac right now (the name is shown). |
| 🔴 **Blocked** | You switched on the kill switch. Nobody can connect until you allow it again. |

---

## 2. One-time setup (about 30 minutes, once)

You only do this once. Claude (or this guide) walks you through each step.

### 2a. Your free web address
1. Go to **duckdns.org** and sign in with GitHub.
2. Type `heartfulness-remote` in "sub domain" and click **add domain**.
   Your address is now `https://heartfulness-remote.duckdns.org`.
3. Keep that page open — you'll paste your server's IP there in step 2b.
   (Never share the "token" shown on that page.)

### 2b. Your server
1. Create a server at Hetzner (type **CX22**, image **Ubuntu 24.04**).
2. Under **Cloud config / User data**, paste the contents of
   `deploy/cloud-init.yaml` and change the one line `HR_DOMAIN=…` to your address.
3. Click **Create**. Copy the server's IP address.
4. Back on duckdns.org, paste the IP into **current ip** and click **update ip**.
5. Wait about 10 minutes. Then open your address in a browser — you should see
   the Heartfulness Remote page.

### 2c. The Mac app
1. Download **Heartfulness-Remote-Mac.zip** from
   https://github.com/videoproduction-ctrl/heartfulness-remote/releases/latest
2. Double-click the zip, then drag **Heartfulness Remote** into **Applications**.
3. Open it. The first time, macOS says it can't verify the app (it's signed for
   your Mac only, not by Apple). Open **System Settings → Privacy & Security**,
   scroll down and click **Open Anyway**.
4. Follow the setup window. It asks you to:
   - type your web address,
   - **Allow** Screen Recording and Accessibility (so it can show your screen
     and move the mouse — click **Allow** / switch them on when macOS asks),
   - allow notifications,
   - turn on the Mac firewall and "stealth mode" (you type your Mac password
     into the macOS box — never into a chat),
   - start automatically when you log in.

### 2d. Your phone (creates your passkey)
1. The Mac app shows a **QR code**.
2. Point your phone's camera at it and tap the link.
3. Tap **Create passkey** and confirm with Face ID / fingerprint.
4. Done — your phone is now trusted and can approve other devices.

> A passkey replaces passwords. It lives in your phone's keychain (iCloud
> Keychain or Google Password Manager) and can't be phished.

---

## 3. Connecting to your Mac

1. Open your web address (or the desktop app).
2. Tap **Sign in with passkey** (first time on a new browser: see section 4).
3. When it says **Online**, click **Connect**.

Your Mac shows a notification and an orange bar across the top of the screen:
**"● (device) is controlling this Mac"** — every time, so you always know.

### During a session
Move the mouse to the top of the window to show the toolbar:

| Button | What it does |
|---|---|
| **Full screen** | Fills your screen; keyboard shortcuts (⌘C, ⌘Tab…) go to the Mac |
| **Display** | Pick which screen to see if your Mac has more than one |
| **Quality** | **Auto** · **Sharp** (best for video editing — crisp detail) · **Smooth** (best for motion) |
| **Sound** | Mute / unmute your Mac's sound |
| **Clipboard** | Copy on one side, paste on the other |
| **Files** | Send files to your Mac (they land in **Downloads › Heartfulness Remote**), or browse your Mac and download files |
| **Ctrl as ⌘** | On a Windows PC, makes Ctrl act like ⌘ |
| **Disconnect** | Ends the session |

The small pill in the corner shows the connection: e.g. **18 ms · 60 fps · 25 Mbps · Direct**.
Green = great, amber = OK, red = slow. "Relay" means it's going through your server
(still fully encrypted) because a direct path wasn't possible.

**Keyboard shortcuts** (hold **Ctrl + Alt + Shift** and press):
**F** full screen · **Q** disconnect · **K** keyboard capture · **U** upload a file ·
**V** send your clipboard · **S** change quality · **H** help.

On a phone or tablet: tap = click, two-finger tap = right-click, two fingers
drag = scroll, press and hold = drag. The keyboard button opens the on-screen keyboard.

---

## 4. Adding a new browser or computer

Every new browser or computer must be approved before it can connect.

1. On the new device, open your web address and **Sign in with passkey**
   (if your passkey isn't on this device, choose "use a phone" and scan with your phone).
2. Give the device a name and tap **Ask for approval**. A **6-digit code** appears.
3. Approve it **either**:
   - **on your phone**: open your web address → Home → the request appears → check the
     code matches → **Approve**; **or**
   - **on your Mac**: the Heartfulness Remote menu shows the request → check the
     code matches → **Approve**.

> **Only approve if the code matches exactly.** If it doesn't, tap **Deny** —
> something is wrong.

**Desktop app (Mac or Windows):** download it from the same Releases page, open
it, type your web address, then click **Sign in** — your browser opens; sign in
there and type the code the app shows. Then approve it as above.

---

## 5. Removing a device

Lost a laptop? Stopped using a browser?
- **On your phone or another device:** Home → **Trusted devices** → **Remove**.
- **On your Mac:** Heartfulness Remote → Dashboard → **Devices** → **Remove**.

It can no longer connect, immediately. (If you later want it back, it must be
approved again.)

---

## 6. The kill switch — stop everything, instantly

If anything ever feels wrong:

| Where | How |
|---|---|
| **Mac menu bar** | Click the Heartfulness Remote icon → **Block all connections** |
| **Mac keyboard** | Press **Control + Option + Command + K** |
| **The orange bar** | Click **Disconnect** (ends the current session) |
| **Your phone** | Home → **Block all connections** → **Block** |

Any session ends at once and nobody can connect. To turn it back on: menu bar →
**Allow connections again**, or on your phone Home → **Allow connections**.

---

## 7. Your access log

Your Mac keeps a private, tamper-evident record of every session, approval and
file transfer. Open **Dashboard → Access Log**. It says **"Log verified ✓"** when
nothing has been altered. A red warning means the log was changed — tell Claude.

---

## 8. It says "Offline" — what to check

Go down this list; most problems are fixed by step 1 or 2.

1. **Is the Mac awake and the app running?** Look for the Heartfulness Remote
   icon in the Mac's menu bar. If it's missing, open the app from Applications.
   If the Mac sleeps, set **System Settings → Battery/Energy → Prevent automatic
   sleeping** (or "Wake for network access").
2. **Is the Mac on the internet?** Open any website on the Mac.
3. **Did you switch on the kill switch?** If the status says **Blocked**, choose
   **Allow connections again**.
4. **Is your web address working?** Open it in a browser. If the page doesn't load:
   - check that your server is running in the Hetzner console (reboot it there if needed),
   - check that duckdns.org still shows your server's IP.
5. **After a Mac app update**, macOS may ask again for **Screen Recording** and
   **Accessibility** — the app reopens the right setup step; just click **Allow**.
6. **Still offline?** Open Claude, type **continue**, and describe what you see.

---

## 9. Staying safe — in plain words

- Everything between your device and your Mac is encrypted end to end. Your
  server only introduces the two sides; it never sees your screen.
- Your Mac only accepts devices **you** approved, and checks a cryptographic
  signature on every connection — even your own server can't pretend to be one.
- Passkeys can't be guessed or phished. There are no passwords to steal.
- Every session shows a banner and a notification on the Mac.
- For the most sensitive work, prefer the desktop app over a browser: the app's
  code is built in, while a web page's code comes from your server.
- Never paste passwords, the DuckDNS token or codes into chats or emails.
