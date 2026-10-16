// "Add a Mac" (PROTOCOL.md §10.2). Typed path: the owner types the Mac ID and
// the code shown on the new Mac. QR path: the phone camera opened
// `#join=<T>.<hostPub>` (already removed from the address bar). Either way the
// new Mac's key is pinned only after its certificate AND hostMac verify.

import type { App, View } from "../app";
import { ApiError } from "../api";
import { type Bytes, b64 } from "../b64";
import { h, replace } from "../dom";
import type { JoinFragment } from "../fragment";
import { formatJoinCodeInput, formatMacId, formatMacIdInput, macId, parseJoinCode, parseMacIdInput, ProtocolError } from "../hr1";
import { icon } from "../icons";
import { beginJoin, findPendingMac, finishJoin, JoinError, type JoinDeps, type PreparedJoin } from "../join";
import { button, card, errorBox, errorMessage, setError, spinner } from "../ui";
import { brand, hero, page } from "./common";

const INTRO = "On the new Mac, open Heartfulness Remote. Scan its code with your phone's camera, or type the Mac ID and code shown on it.";

function friendly(e: unknown): string {
  if (e instanceof JoinError) return e.message;
  if (e instanceof ProtocolError) return `Security check failed: ${e.message}. Nothing was added.`;
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error && e.message === "aborted") return "Cancelled.";
  return errorMessage(e);
}

export function addMacView(app: App, frag: JoinFragment | null): View {
  let destroyed = false;
  let abort: AbortController | null = null;
  let prepared: PreparedJoin | null = null;
  let qrSecret: Bytes | null = frag ? frag.t : null;

  const err = errorBox("add-mac");
  const status = h("p", { class: "status-line", testid: "add-mac-status", attrs: { "aria-live": "polite" } });
  const body = h("div", { class: "stack" });

  const wipeSecret = () => {
    qrSecret?.fill(0);
    qrSecret = null;
  };
  const wipe = () => {
    prepared?.ka.fill(0);
    prepared = null;
    wipeSecret();
  };

  const setStatus = (s: string, busy = false) => replace(status, busy ? spinner(s) : null, s);

  const deps = (): JoinDeps => {
    if (!app.signer) throw new Error("This device's key is not available.");
    return {
      api: app.api,
      proof: () => app.deviceProof(),
      devicePub: app.signer.pub,
      device: () => app.registeredDevice(),
      hostJoined: (hp, ms, ab) => app.waitHostJoined(hp, ms, ab),
    };
  };

  // ---------------------------------------------------------- typed form
  const idInput = h("input", {
    class: "input input-macid",
    testid: "add-mac-id-input",
    attrs: { type: "text", inputmode: "numeric", autocomplete: "off", spellcheck: "false", maxlength: 13, placeholder: "123 456 789", "aria-label": "Mac ID" },
  });
  idInput.id = "add-mac-id";
  idInput.addEventListener("input", () => {
    idInput.value = formatMacIdInput(idInput.value);
  });
  const codeInput = h("input", {
    class: "input input-joincode",
    testid: "add-mac-code-input",
    attrs: {
      type: "text",
      inputmode: "text",
      autocomplete: "off",
      autocapitalize: "characters",
      spellcheck: "false",
      maxlength: 24,
      placeholder: "ABCD-EFGH-IJKL-MNOP",
      "aria-label": "Code",
    },
  });
  codeInput.id = "add-mac-code";
  codeInput.addEventListener("input", () => {
    codeInput.value = formatJoinCodeInput(codeInput.value);
  });

  function showForm(): void {
    abort?.abort();
    abort = null;
    setStatus("");
    const submit = button({ label: "Add Mac", testid: "add-mac-submit", variant: "primary", large: true, icon: "plus", type: "submit" });
    const form = h(
      "form",
      { class: "stack", attrs: { novalidate: true } },
      h("p", { class: "center muted", text: INTRO }),
      h("label", { class: "label", attrs: { for: "add-mac-id" }, text: "Mac ID" }),
      idInput,
      h("label", { class: "label", attrs: { for: "add-mac-code" }, text: "Code" }),
      codeInput,
      h("p", { class: "hint", text: "Both are shown in Heartfulness Remote on the new Mac. The code works once and changes after a while." }),
      submit,
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (submit.disabled) return;
      submit.disabled = true;
      void typedJoin().finally(() => {
        submit.disabled = false;
      });
    });
    replace(body, form, cancelButton());
    if (!destroyed) setTimeout(() => (idInput.value ? codeInput : idInput).focus({ preventScroll: true }), 0);
  }

  async function typedJoin(): Promise<void> {
    setError(err, null);
    const id = parseMacIdInput(idInput.value);
    if (!id) {
      setError(err, "A Mac ID has 9 digits, like 123 456 789.");
      return;
    }
    let t: Bytes;
    try {
      t = parseJoinCode(codeInput.value);
    } catch {
      setError(err, "That code doesn't look right. It has 16 letters and numbers, like ABCD-EFGH-IJKL-MNOP.");
      return;
    }
    const ac = new AbortController();
    abort = ac;
    showWorking("Looking for your Mac…");
    try {
      const d = deps();
      const found = await findPendingMac(d.api, id);
      if (ac.signal.aborted) return;
      setStatus(`Adding “${found.name || "your Mac"}”…`, true);
      prepared = await beginJoin(d, found.hostPub, t);
      if (!prepared.name) prepared.name = found.name;
      await complete(d, ac);
    } catch (e) {
      failed(e, ac);
    } finally {
      t.fill(0);
    }
  }

  // ---------------------------------------------------------- QR path
  async function qrBegin(f: JoinFragment): Promise<void> {
    const hp = b64(f.hostPub);
    if (app.canUse(hp)) {
      wipe();
      showDone(app.macName(hp), app.mac(hp)?.macId ?? (await macId(f.hostPub)), true);
      return;
    }
    const ac = new AbortController();
    abort = ac;
    showWorking("Checking the Mac…");
    try {
      const d = deps();
      const t = qrSecret;
      if (!t) throw new Error("This link was already used. On the Mac, show the code again.");
      prepared = await beginJoin(d, f.hostPub, t);
      wipeSecret();
      if (ac.signal.aborted || destroyed) return;
      abort = null;
      showConfirm(prepared);
    } catch (e) {
      wipeSecret();
      failed(e, ac, await macId(f.hostPub));
    }
  }

  /** A link alone must never add a Mac: the owner confirms what they see. */
  function showConfirm(p: PreparedJoin): void {
    setStatus("");
    const name = p.name || "New Mac";
    replace(
      body,
      h(
        "div",
        { class: "join-confirm", testid: "add-mac-confirm" },
        h("span", { class: "join-confirm-icon" }, icon("display")),
        h("strong", { class: "join-confirm-name", testid: "add-mac-name", text: name }),
        h("span", { class: "mac-id", testid: "add-mac-mac-id", text: `Mac ID ${formatMacId(p.macId)}` }),
      ),
      h("p", { class: "center", text: "Add this Mac to your account? Only continue if it's your Mac and its screen shows the same Mac ID." }),
      button({
        label: "Add this Mac",
        testid: "add-mac-submit",
        variant: "primary",
        large: true,
        icon: "plus",
        onClick: async () => {
          const ac = new AbortController();
          abort = ac;
          showWorking(`Adding “${name}”…`);
          try {
            await complete(deps(), ac);
          } catch (e) {
            failed(e, ac, p.macId);
          }
        },
      }),
      cancelButton(),
    );
  }

  // ---------------------------------------------------------- shared steps
  async function complete(d: JoinDeps, ac: AbortController): Promise<void> {
    const p = prepared;
    if (!p) throw new Error("Please start again.");
    setStatus("Waiting for the Mac to confirm…", true);
    await finishJoin(d, p, ac.signal);
    if (destroyed) return;
    // Verified: the key belongs to the Mac that showed the code.
    await app.pinMac(p.hostPub, p.name);
    const name = p.name || "Your Mac";
    const id = p.macId;
    wipe();
    abort = null;
    app.markApproved(b64(p.hostPub));
    showDone(name, id, false);
  }

  function failed(e: unknown, ac: AbortController, knownMacId?: string): void {
    prepared?.ka.fill(0);
    prepared = null;
    if (destroyed || (ac.signal.aborted && abort !== ac)) return;
    abort = null;
    setStatus("");
    setError(err, friendly(e));
    if (knownMacId && !idInput.value) idInput.value = formatMacId(knownMacId);
    replace(
      body,
      button({ label: "Try again", testid: "add-mac-retry", variant: "primary", large: true, onClick: () => showForm() }),
      cancelButton(),
    );
  }

  function showWorking(text: string): void {
    setError(err, null);
    setStatus(text, true);
    replace(body, cancelButton());
  }

  function showDone(name: string, id: string, already: boolean): void {
    setStatus("");
    setError(err, null);
    replace(
      body,
      h("div", { class: "success-mark", testid: "add-mac-done" }, h("span", { text: "✓" })),
      h("p", { class: "center", text: already ? `“${name}” is already one of your Macs.` : `“${name}” was added to your Macs.` }),
      h("p", { class: "center muted mac-id", text: `Mac ID ${formatMacId(id)}` }),
      button({ label: "Done", testid: "add-mac-home", variant: "primary", large: true, onClick: () => app.goHome() }),
    );
  }

  function cancelButton(): HTMLButtonElement {
    return button({
      label: "Cancel",
      testid: "add-mac-cancel",
      variant: "plain",
      onClick: () => {
        abort?.abort();
        abort = null;
        wipe();
        app.goHome();
      },
    });
  }

  if (frag) void qrBegin(frag);
  else showForm();

  return {
    name: "add-mac",
    el: page(
      "add-mac",
      brand(),
      card({ testid: "add-mac-card" }, hero("plus", "Add a Mac"), status, err, body),
    ),
    destroy() {
      destroyed = true;
      abort?.abort();
      wipe();
    },
  };
}

/** A join link was opened on a device that isn't approved on any Mac yet. */
export function joinNeedsApprovalView(app: App): View {
  return {
    name: "join-needs-approval",
    el: page(
      "join-needs-approval",
      brand(button({ label: "Sign out", testid: "signout-button", variant: "plain", icon: "signout", onClick: () => app.signOut() })),
      card(
        { testid: "join-needs-approval" },
        hero(
          "shield",
          "Approve this device first",
          "To add a Mac, use a phone or computer that's already approved on one of your Macs. Or first approve this device on one of your Macs, then scan the new Mac's code again.",
          "tone-warn",
        ),
        button({ label: "Continue", testid: "join-needs-approval-continue", variant: "primary", large: true, onClick: () => app.routeByStatus() }),
      ),
    ),
  };
}
