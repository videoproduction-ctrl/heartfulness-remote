// First-time setup from the Mac's QR code (PROTOCOL.md §4):
// derive Kc/Ka from T, create the owner passkey, create the device key,
// prove knowledge of T with the setup MAC, then wait for the Mac to approve.

import type { App, View } from "../app";
import { ApiError, type Flow } from "../api";
import { b64 } from "../b64";
import { cleanDeviceName, defaultDeviceName } from "../device-name";
import { h, replace } from "../dom";
import type { SetupFragment } from "../fragment";
import { fingerprint, setupKeys, setupMac, verifyCert } from "../hr1";
import { button, card, errorBox, errorMessage, setError, spinner } from "../ui";
import { createPasskey, webauthnAvailable } from "../webauthn";
import { brand, hero, page } from "./common";

export type { SetupFragment };

const APPROVAL_WAIT_MS = 5 * 60 * 1000;

export function setupView(app: App, frag: SetupFragment): View {
  let destroyed = false;
  let kc: Uint8Array | null = null;
  let ka: Uint8Array | null = null;
  let t: Uint8Array | null = frag.t;
  const hostPub = frag.hostPub;
  let flow: Flow | null = null;
  const cleanups: Array<() => void> = [];

  const status = h("p", { class: "status-line", testid: "setup-status", attrs: { "aria-live": "polite" } });
  const err = errorBox("setup-error");
  const body = h("div", { class: "stack" });
  const macKey = h("p", { class: "fineprint", testid: "setup-mac-fingerprint" });
  void fingerprint(hostPub).then((fp) => {
    macKey.textContent = `Mac security key: ${fp}`;
  });

  const wipe = () => {
    kc?.fill(0);
    ka?.fill(0);
    t?.fill(0);
    kc = ka = t = null;
  };

  const setStatus = (s: string, busy = false) => {
    replace(status, busy ? spinner(s) : null, s);
  };

  const nameInput = h("input", {
    class: "input",
    testid: "setup-device-name",
    attrs: { type: "text", maxlength: 48, autocomplete: "off", "aria-label": "Name for this device" },
  });
  nameInput.id = "setup-device-name";
  nameInput.value = defaultDeviceName({
    userAgent: navigator.userAgent,
    maxTouchPoints: navigator.maxTouchPoints,
    app: app.platform.kind === "tauri",
  });

  async function begin(): Promise<void> {
    setError(err, null);
    setStatus("Checking with your Mac…", true);
    replace(body);
    try {
      if (!t) throw new Error("This setup link was already used. On your Mac, show a new QR code and scan it again.");
      if (!kc || !ka) ({ kc, ka } = await setupKeys(t));
      flow = await app.api.setupBegin(b64(hostPub), b64(kc));
    } catch (e) {
      if (destroyed) return;
      setStatus("");
      if (e instanceof ApiError && (e.status === 400 || e.status === 404 || e.status === 409 || e.status === 410)) {
        setError(err, "This setup code is not valid any more. On your Mac, show a new setup QR code and scan it again.");
      } else setError(err, e);
      replace(body, button({ label: "Try again", testid: "setup-retry", onClick: begin }));
      return;
    }
    if (destroyed) return;
    setStatus("");
    showCreate();
  }

  function showCreate(): void {
    if (!webauthnAvailable()) {
      setError(err, "This browser doesn't support passkeys. Please open the link in Safari (iPhone/iPad), Chrome or Edge.");
      return;
    }
    replace(
      body,
      h("label", { class: "label", attrs: { for: "setup-device-name" }, text: "Name this device" }),
      nameInput,
      h("p", { class: "hint", text: "You'll see this name in your list of trusted devices." }),
      button({
        label: "Create passkey",
        testid: "setup-create-passkey",
        variant: "primary",
        large: true,
        icon: "key",
        // WebAuthn must be called directly from the tap (Safari requires a user gesture).
        onClick: () => createAndFinish(),
      }),
    );
  }

  async function createAndFinish(): Promise<void> {
    setError(err, null);
    const name = cleanDeviceName(nameInput.value) || "My phone";
    if (!flow) return begin();
    let credential: unknown;
    try {
      credential = await createPasskey(flow.options);
    } catch (e) {
      setError(err, e);
      return;
    }
    setStatus("Saving…", true);
    try {
      const signer = await app.platform.signer(true);
      if (!signer) throw new Error("Could not create this device's security key.");
      if (!ka) throw new Error("Setup secret missing.");
      const kind = app.platform.deviceKind;
      const mac = await setupMac(ka, hostPub, signer.pub, name, kind);
      await app.api.setupFinish({
        flowId: flow.flowId,
        credential,
        device: { pub: b64(signer.pub), name, kind },
        setupMac: b64(mac),
      });
      // The QR code came from the Mac's own screen: its host key is authentic.
      await app.platform.pinHost(hostPub);
      app.pinned = hostPub;
      wipe();
    } catch (e) {
      if (destroyed) return;
      setStatus("");
      flow = null;
      setError(err, e instanceof ApiError && e.status === 410 ? "The setup took too long. Please try again." : e);
      replace(body, button({ label: "Try again", testid: "setup-retry", onClick: begin }));
      return;
    }
    await waitForApproval();
  }

  async function waitForApproval(): Promise<void> {
    replace(body);
    setStatus("Waiting for your Mac to confirm this device…", true);
    try {
      await app.connectSignal();
    } catch (e) {
      setStatus("");
      setError(err, e);
      replace(body, button({ label: "Continue", testid: "setup-continue", variant: "primary", onClick: () => app.boot() }));
      return;
    }
    if (destroyed) return;
    const done = () => {
      if (destroyed) return;
      for (const c of cleanups.splice(0)) c();
      app.status = "approved";
      replace(
        body,
        h("div", { class: "success-mark", testid: "setup-done" }, h("span", { text: "✓" })),
        h("p", { class: "center", text: "All set! This device can now connect to your Mac." }),
      );
      setStatus("");
      setTimeout(() => app.routeByStatus(), 1200);
    };
    if (app.status === "approved") {
      done();
      return;
    }
    const sig = app.signal!;
    cleanups.push(app.on("status", () => app.status === "approved" && done()));
    cleanups.push(
      sig.on("pair-approved", (m) => {
        void verifyCert(m["cert"], hostPub, app.signer?.pub)
          .then(done)
          .catch((e: unknown) => setError(err, `Your Mac's confirmation could not be verified: ${errorMessage(e)}`));
      }),
    );
    cleanups.push(
      sig.on("pair-denied", () => {
        setStatus("");
        setError(err, "Your Mac did not approve this device. Show a new setup code on your Mac and try again.");
      }),
    );
    const poll = setInterval(() => void app.refreshMe(), 4000);
    cleanups.push(() => clearInterval(poll));
    const timeout = setTimeout(() => {
      setStatus("");
      setError(err, "Your Mac hasn't confirmed this device yet. Make sure Heartfulness Remote is running on your Mac, then tap Continue.");
      replace(body, button({ label: "Continue", testid: "setup-continue", variant: "primary", onClick: () => app.boot() }));
    }, APPROVAL_WAIT_MS);
    cleanups.push(() => clearTimeout(timeout));
  }

  void begin();

  return {
    name: "setup",
    el: page(
      "setup",
      brand(),
      card(
        { testid: "setup-card" },
        hero("heart", "Set up Heartfulness Remote", "Create a passkey to protect access to your Mac. No password needed — you'll use Face ID, Touch ID or your device PIN."),
        status,
        err,
        body,
        macKey,
      ),
    ),
    destroy() {
      destroyed = true;
      for (const c of cleanups.splice(0)) c();
      wipe();
    },
  };
}
