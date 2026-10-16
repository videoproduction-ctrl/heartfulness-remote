// Asking one Mac for access (PROTOCOL.md §5, routed by hostPub per §10.3):
// commit → challenge → reveal → SAS. The device only reveals its key after the
// host committed to `na` (signed challenge), so neither side can grind the
// 6-digit code. The Mac's key is pinned only after the SAS-confirmed challenge
// key issued a valid certificate for exactly this device.

import type { App, View } from "../app";
import { type Bytes, b64, equalBytes, randomBytes, unb64Len } from "../b64";
import { cleanDeviceName, defaultDeviceName } from "../device-name";
import { h, replace } from "../dom";
import { formatMacId, formatSAS, pairCommit, parsePairChallenge, ProtocolError, sas, verifyCert, verifyPairChallenge } from "../hr1";
import { aboutMac, pairRevealMsg, pairStartMsg } from "../messages";
import { type Msg, waitFor } from "../signal";
import { button, card, errorBox, errorMessage, setError, spinner } from "../ui";
import { brand, hero, page } from "./common";

const CHALLENGE_TIMEOUT_MS = 60_000;
const APPROVAL_TIMEOUT_MS = 5 * 60_000;

/** Plain-language text for pair-denied reasons (agent pairing.go, server hub.go). */
export function denialText(reason: unknown): string {
  switch (reason) {
    case "expired":
    case "timeout":
      return "The request expired before it was approved. You can try again.";
    case "rate-limited":
    case "too-many":
      return "Too many requests were denied recently. Please wait an hour, or approve directly on your Mac.";
    case "too-many-pending":
      return "Too many devices are waiting for approval right now. Approve or deny them first, then try again.";
    case "bad-commit":
    case "commit-mismatch":
    case "invalid":
      return "Your Mac rejected the request because a security check failed. Please try again.";
    case "revoked":
      return "This device was removed from your Mac before. Remove it from the list on your Mac or phone, then try again.";
    case "host-offline":
    case "host-reconnected":
    case "unavailable":
      return "Your Mac went offline before it could approve this device. Make sure it's on and running Heartfulness Remote, then try again.";
    default:
      return "The request was declined on your Mac or phone. If that was a mistake, try again.";
  }
}

/** Plain-language text for a server {type:"error"} reply during pairing. */
export function pairErrorText(code: unknown): string {
  switch (code) {
    case "host-offline":
      return "Your Mac is offline. It must be on and running Heartfulness Remote to approve this device.";
    case "pairing-in-progress":
      return "This device is already waiting for approval. Check your Mac or phone.";
    case "too-many-pending":
      return "Too many devices are waiting for approval right now. Approve or deny them first, then try again.";
    case "rate-limited":
      return "Too many attempts. Please wait a few minutes and try again.";
    case "unknown-host":
      return "This Mac is no longer part of your account.";
    default:
      return `Your Mac couldn't be reached (${typeof code === "string" && /^[\w-]{1,40}$/.test(code) ? code : "error"}). Please try again.`;
  }
}

export function pairView(app: App, target: string | null): View {
  let destroyed = false;
  let abort: AbortController | null = null;
  const offs: Array<() => void> = [];
  const err = errorBox("pair");
  const body = h("div", { class: "stack" });
  const hostLine = h("p", { class: "status-line", testid: "pair-host-status" });
  const macLine = h("p", { class: "center mac-ident-line", testid: "pair-mac" });
  const targetKey: Bytes | null = target ? safeKey(target) : null;
  const macName = () => (target ? app.macName(target) : "your Mac");
  // Offer a way back when there is somewhere else to go (other Macs).
  const canGoBack = () => app.macs.length > 1 || app.usableMacs.length > 0;

  const nameInput = h("input", {
    class: "input",
    testid: "pair-name-input",
    attrs: { type: "text", maxlength: 48, autocomplete: "off", "aria-label": "Name for this device" },
  });
  nameInput.id = "pair-device-name";
  const registered = app.me?.devices.find((d) => d.pub === app.devicePub)?.name;
  nameInput.value =
    registered ||
    defaultDeviceName({
      userAgent: navigator.userAgent,
      maxTouchPoints: navigator.maxTouchPoints,
      app: app.platform.kind === "tauri",
    });

  const renderHost = () => {
    const m = target ? app.mac(target) : undefined;
    if (!m) hostLine.textContent = "";
    else if (!m.online) hostLine.textContent = `“${m.name || "This Mac"}” is offline. It must be on and running Heartfulness Remote to approve this device.`;
    else hostLine.textContent = "";
    replace(
      macLine,
      m ? h("strong", { testid: "pair-mac-name", text: m.name || "Your Mac" }) : null,
      m ? h("span", { class: "mac-id", testid: "pair-mac-id", text: `Mac ID ${formatMacId(m.macId)}` }) : null,
    );
    macLine.hidden = !m;
  };
  offs.push(app.on("macs", renderHost));
  renderHost();

  // This device may be approved on the target Mac while this screen is shown
  // (e.g. from another tab). Our own success shows its check mark first.
  let finished = false;
  const approvedElsewhere = () => {
    if (!finished && target && app.canUse(target) && !abort) app.routeByStatus();
  };
  offs.push(app.on("status", approvedElsewhere));
  offs.push(app.on("macs", approvedElsewhere));

  function showIntro(): void {
    abort?.abort();
    abort = null;
    replace(
      body,
      h("label", { class: "label", attrs: { for: "pair-device-name" }, text: "Name this device" }),
      nameInput,
      h("p", { class: "hint", text: "You'll see this name on your Mac and in your list of trusted devices." }),
      button({ label: "Ask for approval", testid: "pair-start-button", variant: "primary", large: true, icon: "shield", onClick: start }),
      canGoBack() ? button({ label: "Back to my Macs", testid: "pair-back", variant: "plain", onClick: () => app.goHome() }) : null,
    );
  }

  async function start(): Promise<void> {
    setError(err, null);
    const sig = app.signal;
    const signer = app.signer;
    if (!sig || !signer || !sig.isReady) throw new Error("Not connected to the server yet. Please wait a moment and try again.");
    if (!target || !targetKey) throw new Error("No Mac is connected to your account yet.");
    const name = cleanDeviceName(nameInput.value) || "My device";
    const kind = app.platform.deviceKind;
    const ac = new AbortController();
    abort = ac;
    const mine = (m: Msg) => aboutMac(m, target);

    replace(body, h("p", { class: "status-line", testid: "pair-status" }, spinner(""), ` Contacting “${macName()}”…`), cancelButton());

    try {
      const nd = randomBytes(32);
      const devicePub = signer.pub;
      const commit = await pairCommit(devicePub, nd);
      let requestId: string | null = null;
      offs.push(
        sig.on("pair-pending", (m) => {
          if (typeof m["requestId"] === "string" && requestId === null && mine(m)) requestId = m["requestId"];
        }),
      );
      // Only errors about OUR pairing (pair-start errors, or ones naming our requestId) abort it.
      const ours = (m: Msg) =>
        mine(m) &&
        (m.type === "pair-denied"
          ? requestId === null || m["requestId"] === undefined || m["requestId"] === requestId
          : m["for"] === "pair-start" || (requestId !== null && m["requestId"] === requestId));
      const failure = waitFor(sig, ["pair-denied", "error"], ours, APPROVAL_TIMEOUT_MS + CHALLENGE_TIMEOUT_MS, ac.signal).then(
        (m) => Promise.reject(m),
        () => new Promise<never>(() => undefined),
      );
      if (!sig.send(pairStartMsg(target, name, kind, commit))) throw new Error("Not connected to the server. Try again.");

      // 1) Wait for the host's signed challenge (commitment to na).
      const chMsg = await Promise.race([
        waitFor(sig, ["pair-challenge"], (m) => mine(m) && (requestId === null || m["requestId"] === requestId), CHALLENGE_TIMEOUT_MS, ac.signal),
        failure,
      ]);
      const ch = parsePairChallenge(chMsg);
      if (!(await verifyPairChallenge(ch.hostPub, ch.sig, ch.requestId, commit, ch.na))) {
        throw new Error("The challenge was not signed correctly. Do not continue; try again later.");
      }
      // The Mac that answered must be the Mac we asked.
      if (!equalBytes(ch.hostPub, targetKey)) throw new ProtocolError("a different Mac answered this request");
      const rid = b64(ch.requestId);

      // 2) Reveal our key and nonce, then show the SAS.
      if (!sig.send(pairRevealMsg(rid, devicePub, nd))) throw new Error("Not connected to the server. Try again.");
      const code = await sas(ch.hostPub, devicePub, nd, ch.na);
      showSAS(code);

      // 3) Wait for the decision.
      const res = await Promise.race([
        waitFor(sig, ["pair-approved"], (m) => mine(m) && (m["requestId"] === undefined || m["requestId"] === rid), APPROVAL_TIMEOUT_MS, ac.signal),
        failure,
      ]);
      await finishApproved(res, ch.hostPub, devicePub);
      ac.abort(); // release the remaining listeners
    } catch (e) {
      if (destroyed || ac.signal.aborted) return;
      abort = null;
      ac.abort();
      if (e && typeof e === "object" && "type" in e) {
        const m = e as Msg;
        if (m.type === "error" && m["code"] === "already-approved") {
          void app.refreshMe().then(() => app.boot());
          return;
        }
        setError(err, m.type === "pair-denied" ? denialText(m["reason"]) : pairErrorText(m["code"]));
      } else if (e instanceof ProtocolError) {
        setError(err, `Security warning: ${e.message}. Do not continue — someone may be trying to impersonate your Mac.`);
      } else if (e instanceof Error && e.message === "timeout") {
        setError(err, `No answer from “${macName()}”. Make sure it's on and running Heartfulness Remote, then try again.`);
      } else {
        setError(err, errorMessage(e));
      }
      replace(
        body,
        button({ label: "Try again", testid: "pair-retry", variant: "primary", large: true, onClick: () => showIntro() }),
        canGoBack() ? button({ label: "Back to my Macs", testid: "pair-back", variant: "plain", onClick: () => app.goHome() }) : null,
      );
    }
  }

  async function finishApproved(m: Msg, hostPub: Bytes, devicePub: Bytes): Promise<void> {
    // Pin only a host key that (a) produced the SAS the user compared and
    // (b) issued a valid certificate for exactly our device key.
    await verifyCert(m["cert"], hostPub, devicePub);
    finished = true;
    await app.pinMac(hostPub, target ? app.macName(target) : "");
    abort = null;
    replace(
      body,
      h("div", { class: "success-mark", testid: "pair-approved" }, h("span", { text: "✓" })),
      h("p", { class: "center", text: `Approved! This device can now connect to “${macName()}”.` }),
    );
    app.markApproved(b64(hostPub));
    setTimeout(() => {
      if (!destroyed) app.routeByStatus();
    }, 1200);
  }

  function showSAS(code: string): void {
    replace(
      body,
      h("p", { class: "center sas-intro", text: `On “${macName()}” or on a phone you use with it, approve this device and check the code matches:` }),
      h("div", { class: "sas", testid: "pair-sas", attrs: { "aria-label": `Code ${code.split("").join(" ")}`, "data-sas": code }, text: formatSAS(code) }),
      h("p", { class: "status-line", testid: "pair-status" }, spinner(""), " Waiting for approval…"),
      h("p", { class: "hint center", text: "If the code is different, deny the request — someone may be trying to get in." }),
      cancelButton(),
    );
  }

  function cancelButton(): HTMLButtonElement {
    return button({ label: "Cancel", testid: "pair-cancel", variant: "plain", onClick: () => showIntro() });
  }

  showIntro();

  const subtitle = target
    ? "For your security, each Mac must approve this device — on the Mac itself, or on a phone you already use with it. Check that the Mac ID below matches the one shown on the Mac."
    : "For your security, every new device must be approved on your Mac — or on a phone you already use with Heartfulness Remote.";

  return {
    name: "pair",
    el: page(
      "pair",
      brand(button({ label: "Sign out", testid: "signout-button", variant: "plain", icon: "signout", onClick: () => app.signOut() })),
      card({ testid: "pair-card" }, hero("shield", "Approve this device", subtitle), macLine, hostLine, err, body),
    ),
    destroy() {
      destroyed = true;
      abort?.abort();
      for (const o of offs.splice(0)) o();
    },
  };
}

function safeKey(pub: string): Bytes | null {
  try {
    return unb64Len(pub, 32);
  } catch {
    return null;
  }
}
