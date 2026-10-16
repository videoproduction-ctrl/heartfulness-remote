// Home: "Your Macs" — one card per Mac (status, Mac ID, Connect / Ask for
// access, Block / Allow, details menu), "Add a Mac", the approvals inbox,
// trusted devices (with the Macs each is approved on) and passkeys.
// With exactly one Mac it looks like the single-Mac home: one big card.

import type { App, Approval, Mac, View } from "../app";
import type { DeviceInfo, PasskeyInfo } from "../api";
import { h, replace } from "../dom";
import { fingerprint, formatMacId, formatSAS } from "../hr1";
import { type IconName, icon } from "../icons";
import { button, card, confirmDialog, formatDate, formatRelative, iconButton, openSheet, toast } from "../ui";
import { createPasskey, webauthnAvailable } from "../webauthn";
import { brand, page } from "./common";

type StatusKind = "online" | "offline" | "busy" | "blocked" | "checking";

function kindIcon(kind: string): IconName {
  if (kind === "app") return "laptop";
  if (/phone|mobile/i.test(kind)) return "phone";
  return "display";
}

function kindLabel(kind: string): string {
  if (kind === "app") return "Desktop app";
  if (kind === "browser") return "Web browser";
  return kind;
}

/** Status shown on a Mac's card (Online / Offline / Someone connected / Blocked). */
export function macStatus(m: Pick<Mac, "online" | "state" | "sessionDeviceName">, signalReady: boolean, reconnecting = false): { kind: StatusKind; title: string; detail: string } {
  if (!signalReady) return { kind: "checking", title: "Checking…", detail: reconnecting ? "Reconnecting to the server…" : "Contacting the server…" };
  if (!m.online) return { kind: "offline", title: "Offline", detail: "This Mac isn't reachable right now." };
  if (m.state === "blocked") return { kind: "blocked", title: "Blocked", detail: "All connections to this Mac are blocked." };
  if (m.state === "in-session") {
    return { kind: "busy", title: "Someone connected", detail: m.sessionDeviceName ? `${m.sessionDeviceName} is using this Mac.` : "Another device is using this Mac." };
  }
  return { kind: "online", title: "Online", detail: "Ready to connect." };
}

/**
 * Older tests and docs address the first card with the single-Mac ids
 * (connect-button, block-button, allow-button). They sit on the button's label
 * so the card's own ids (mac-connect, …) stay on the real button.
 */
function legacyLabelId(b: HTMLButtonElement, id: string | null): HTMLButtonElement {
  const l = b.querySelector<HTMLElement>(".btn-label");
  if (l && id) l.dataset["testid"] = id;
  return b;
}

function setDisabled(b: HTMLButtonElement, disabled: boolean): void {
  b.disabled = disabled;
  // Also mark the label (legacy id) as disabled for assistive tech and test tools.
  if (disabled) b.setAttribute("aria-disabled", "true");
  else b.removeAttribute("aria-disabled");
}

function setTestId(el: HTMLElement, id: string | null): void {
  if (id) el.dataset["testid"] = id;
  else delete el.dataset["testid"];
}

interface MacCard {
  el: HTMLElement;
  update(m: Mac, first: boolean, single: boolean): void;
}

export function homeView(app: App): View {
  const offs: Array<() => void> = [];
  const myPub = app.devicePub;
  const approvedAnywhere = () => app.status === "approved";

  // ---------------------------------------------------------- Mac cards
  function macCard(pub: string): MacCard {
    const nameEl = h("strong", { class: "mac-name", testid: "mac-name" });
    const idEl = h("span", { class: "mac-id", testid: "mac-id" });
    const menuBtn = iconButton("more", "Details", "mac-menu", () => openMacMenu(pub));
    const head = h(
      "div",
      { class: "mac-head" },
      h("span", { class: "mac-icon", attrs: { "aria-hidden": "true" } }, icon("display")),
      h("div", { class: "mac-ident" }, nameEl, idEl),
      menuBtn,
    );
    const dot = h("span", { class: "status-dot", attrs: { "aria-hidden": "true" } });
    const titleLabel = h("span");
    let titleEl: HTMLElement = h("h2", { class: "status-title", testid: "mac-status-title" }, titleLabel);
    const detail = h("p", { class: "status-detail", testid: "mac-status-detail" });
    const statusText = h("div", { class: "status-text" }, titleEl, detail);
    const statusHead = h("div", { class: "status-head", attrs: { "aria-live": "polite" } }, dot, statusText);
    const help = h("button", { class: "link-btn", testid: "offline-help", text: "Why offline?", attrs: { type: "button" } });
    help.addEventListener("click", showOfflineHelp);
    const note = h("p", { class: "mac-note", testid: "mac-note" });
    const actions = h("div", { class: "mac-actions" });
    const el = h("section", { class: "card status-card mac-card", testid: "mac-card", attrs: { "data-host-pub": pub } }, head, statusHead, help, note, actions);
    let actionsSig = "";
    let actionButtons: { connect?: HTMLButtonElement; ask?: HTMLButtonElement; block?: HTMLButtonElement; allow?: HTMLButtonElement } = {};

    function update(m: Mac, first: boolean, single: boolean): void {
      const ready = app.signalState === "ready";
      const st = macStatus(m, ready, app.signalState === "reconnecting");
      const usable = app.canUse(pub);
      const pinned = app.pins.has(pub);
      el.dataset["state"] = st.kind;
      el.dataset["macId"] = m.macId;
      el.dataset["deviceStatus"] = m.deviceStatus;
      statusHead.dataset["state"] = st.kind;
      setTestId(statusHead, first ? "home-status" : null);
      setTestId(statusText, first ? "home-status-text" : null);
      setTestId(titleLabel, first ? "home-status-title" : null);
      // One Mac: its status is the page's heading. Several: "Your Macs" is.
      const tag = single ? "H1" : "H2";
      if (titleEl.tagName !== tag) {
        const next = h(single ? "h1" : "h2", { class: "status-title", testid: "mac-status-title" }, titleLabel);
        titleEl.replaceWith(next);
        titleEl = next;
      }
      nameEl.textContent = m.name || "Mac";
      idEl.textContent = formatMacId(m.macId);
      idEl.setAttribute("aria-label", `Mac ID ${m.macId.split("").join(" ")}`);
      menuBtn.setAttribute("aria-label", `Details for ${m.name || "this Mac"}`);
      titleLabel.textContent = st.title;
      detail.textContent = st.detail;
      help.hidden = st.kind !== "offline";

      let noteText = "";
      if (m.deviceStatus === "approved" && !pinned) {
        noteText = "This device can't verify this Mac's security key, so it can't connect. Remove this device from the Mac's list of trusted devices, then ask for access again.";
      } else if (m.deviceStatus === "pending") noteText = "This device is waiting for approval on this Mac.";
      else if (m.deviceStatus === "revoked") noteText = "This device was removed from this Mac.";
      else if (m.deviceStatus === "unknown") noteText = "This device isn't approved on this Mac yet.";
      note.textContent = noteText;
      note.hidden = noteText === "";

      // Rebuild the buttons only when their shape changes (keeps focus / busy state).
      const shape = usable ? (m.state === "blocked" ? "allow" : "connect") : m.deviceStatus === "approved" ? "none" : "ask";
      const sig = `${shape}|${first}`;
      if (sig !== actionsSig) {
        actionsSig = sig;
        actionButtons = {};
        const kids: HTMLElement[] = [];
        if (shape === "connect") {
          actionButtons.connect = legacyLabelId(
            button({ label: "Connect", testid: "mac-connect", variant: "primary", large: true, icon: "display", onClick: () => app.goSession(pub) }),
            first ? "connect-button" : null,
          );
          actionButtons.block = legacyLabelId(
            button({ label: "Block all connections", testid: "mac-block", variant: "plain", icon: "block", onClick: () => block(pub) }),
            first ? "block-button" : null,
          );
          actionButtons.block.classList.add("btn-danger-text");
          kids.push(actionButtons.connect, actionButtons.block);
        } else if (shape === "allow") {
          kids.push(h("p", { class: "muted", text: "This Mac is refusing all connections until you allow them again." }));
          actionButtons.allow = legacyLabelId(
            button({
              label: "Allow connections",
              testid: "mac-allow",
              variant: "primary",
              large: true,
              icon: "play",
              onClick: async () => {
                await app.killSwitch(pub, "resume");
                toast(`Asked “${app.macName(pub)}” to allow connections again.`, "success");
              },
            }),
            first ? "allow-button" : null,
          );
          kids.push(actionButtons.allow);
        } else if (shape === "ask") {
          actionButtons.ask = button({ label: "Ask for access", testid: "mac-ask-access", variant: "primary", large: true, icon: "shield", onClick: () => app.goPair(pub) });
          kids.push(actionButtons.ask);
        }
        replace(actions, kids);
        actions.hidden = kids.length === 0;
      }
      const b = actionButtons;
      if (b.connect) setDisabled(b.connect, !(st.kind === "online" || st.kind === "busy"));
      if (b.block) setDisabled(b.block, !ready || !m.online);
      if (b.allow) setDisabled(b.allow, !ready || !m.online);
      if (b.ask) setDisabled(b.ask, !ready || !m.online);
    }

    return { el, update };
  }

  async function block(pub: string): Promise<void> {
    const name = app.macName(pub);
    if (
      await confirmDialog({
        title: `Block all connections to “${name}”?`,
        text: "Any current session on this Mac ends immediately, and no device can connect to it until you choose “Allow connections” here or on the Mac.",
        confirm: "Block",
        danger: true,
        testid: "block-confirm",
      })
    ) {
      await app.killSwitch(pub, "kill");
      toast(`Asked “${name}” to block all connections.`, "success");
    }
  }

  function openMacMenu(pub: string): void {
    const m = app.mac(pub);
    if (!m) return;
    const statusText =
      m.deviceStatus === "approved"
        ? app.pins.has(pub)
          ? "Approved"
          : "Approved, but its key is missing here"
        : m.deviceStatus === "pending"
          ? "Waiting for approval"
          : m.deviceStatus === "revoked"
            ? "Removed"
            : "Not approved yet";
    const fp = h("span", { class: "mono", testid: "mac-fingerprint", text: app.pins.has(pub) ? "…" : "Not verified on this device" });
    const pin = app.pinBytes(pub);
    if (pin) void fingerprint(pin).then((f) => (fp.textContent = f));
    const s = openSheet({
      title: m.name || "Mac",
      testid: "mac-menu-sheet",
      content: [
        h(
          "dl",
          { class: "details" },
          h("dt", { text: "Mac ID" }),
          h("dd", { class: "mono", testid: "mac-menu-mac-id", text: formatMacId(m.macId) }),
          h("dt", { text: "This device" }),
          h("dd", { testid: "mac-menu-device-status", text: statusText }),
          h("dt", { text: "Security key" }),
          h("dd", null, fp),
          m.lastSeen ? h("dt", { text: "Last online" }) : null,
          m.lastSeen ? h("dd", { text: formatRelative(m.lastSeen) }) : null,
        ),
        approvedAnywhere()
          ? button({
              label: "Remove this Mac from my account",
              testid: "mac-remove",
              variant: "plain",
              icon: "trash",
              onClick: async () => {
                s.close();
                const name = m.name || "this Mac";
                const ok = await confirmDialog({
                  title: `Remove “${name}”?`,
                  text: "It disappears from your Macs and nobody can connect to it through your account any more. The Mac then shows a new code, so you can add it again later.",
                  confirm: "Remove",
                  danger: true,
                  testid: "mac-remove-confirm",
                });
                if (!ok) return;
                await app.removeMac(pub);
                toast(`“${name}” was removed from your account.`, "success");
              },
            })
          : null,
      ],
    });
    s.body.querySelector<HTMLElement>("[data-testid=mac-remove]")?.classList.add("btn-danger-text");
  }

  const heading = h("h1", { class: "section-title", testid: "macs-heading", text: "Your Macs" });
  const intro = h("p", { class: "muted section-intro", testid: "macs-intro" });
  const macsList = h("div", { class: "macs-list", testid: "macs-list" });
  const addMac = button({ label: "Add a Mac", testid: "add-mac-button", variant: "secondary", icon: "plus", onClick: () => app.goAddMac() });
  addMac.classList.add("add-mac-btn");
  const cards = new Map<string, MacCard>();

  function renderMacs(): void {
    const macs = app.macs;
    const single = macs.length <= 1;
    heading.hidden = single;
    const approved = approvedAnywhere();
    intro.textContent = approved ? "" : "Choose a Mac to ask for access. For your security, each Mac must approve this device before it can connect.";
    intro.hidden = approved;
    addMac.hidden = !approved;
    for (const pub of [...cards.keys()]) {
      if (!macs.some((m) => m.pub === pub)) {
        cards.get(pub)!.el.remove();
        cards.delete(pub);
      }
    }
    macs.forEach((m, i) => {
      let c = cards.get(m.pub);
      if (!c) {
        c = macCard(m.pub);
        cards.set(m.pub, c);
      }
      c.update(m, i === 0, single);
      // Keep DOM order = server order without moving nodes needlessly (moving blurs focus).
      if (macsList.children[i] !== c.el) macsList.insertBefore(c.el, macsList.children[i] ?? null);
    });
    if (macs.length === 0) {
      if (!macsList.querySelector(".macs-empty")) {
        macsList.appendChild(h("p", { class: "muted center macs-empty", testid: "macs-empty", text: "No Macs in your account yet. Open Heartfulness Remote on your Mac to add it." }));
      }
    } else macsList.querySelector(".macs-empty")?.remove();
  }

  // ---------------------------------------------------------- approvals
  const approvalsList = h("div", { class: "list", testid: "approvals-list" });
  const approvalsCard = card({ class: "approvals-card", testid: "approvals", title: "Approval needed", icon: "shield" }, approvalsList);

  function approvalItem(a: Approval): HTMLElement {
    const mac = app.mac(a.hostPub);
    const macName = app.macName(a.hostPub);
    const head = h(
      "div",
      { class: "item-head" },
      h("span", { class: "item-icon" }, icon(kindIcon(a.req.kind))),
      h(
        "div",
        { class: "item-text" },
        h("strong", { testid: "approval-name", text: a.req.name || "Unnamed device" }),
        h("span", { class: "muted", testid: "approval-kind", text: `${kindLabel(a.req.kind)} wants to use “${macName}”` }),
        mac ? h("span", { class: "muted mac-id-small", testid: "approval-mac", text: `${macName} · Mac ID ${formatMacId(mac.macId)}` }) : null,
      ),
    );
    const item = h(
      "div",
      {
        class: "approval-item",
        testid: "approval-item",
        attrs: { "data-request-id": a.requestId, "data-host-pub": a.hostPub, "data-state": a.error || !a.sas ? "invalid" : a.state },
      },
      head,
    );
    if (a.error || !a.sas) {
      item.appendChild(h("p", { class: "error-box", testid: "approval-error", text: a.error ?? "This request could not be verified." }));
      item.appendChild(
        h("div", { class: "row-end" }, button({ label: "Deny", testid: "approval-deny", variant: "danger", onClick: () => app.deny(a.key) })),
      );
      return item;
    }
    item.appendChild(h("p", { class: "muted", text: "Only approve if this code matches the one shown on the new device:" }));
    item.appendChild(h("div", { class: "sas sas-small", testid: "approval-sas", text: formatSAS(a.sas), attrs: { "data-sas": a.sas } }));
    if (a.state === "sent") {
      item.appendChild(h("p", { class: "status-line", testid: "approval-sent", text: `Approved. Waiting for “${macName}” to confirm…` }));
      return item;
    }
    item.appendChild(
      h(
        "div",
        { class: "row-end" },
        button({ label: "Deny", testid: "approval-deny", variant: "secondary", onClick: () => app.deny(a.key) }),
        button({
          label: "Approve",
          testid: "approval-approve",
          variant: "primary",
          icon: "check",
          disabled: a.state !== "open",
          onClick: () => app.approve(a.key),
        }),
      ),
    );
    return item;
  }

  function renderApprovals(): void {
    const list = [...app.approvals.values()];
    approvalsCard.hidden = list.length === 0;
    replace(approvalsList, list.map(approvalItem));
  }

  // ---------------------------------------------------------- devices
  const devicesList = h("div", { class: "list", testid: "devices-list" });
  const devicesCard = card({ testid: "devices", title: "Trusted devices", icon: "display" }, devicesList);

  function deviceItem(d: DeviceInfo): HTMLElement {
    const mine = d.pub === myPub;
    const approvedOn = d.approvals.filter((a) => a.status === "approved" && app.mac(a.hostPub));
    const pendingOn = d.approvals.filter((a) => a.status === "pending" && app.mac(a.hostPub));
    const meta: string[] = [kindLabel(d.kind)];
    if (approvedOn.length === 0 && pendingOn.length > 0) meta.push("waiting for approval");
    else if (d.lastSeen) meta.push(`last used ${formatRelative(d.lastSeen)}`);
    else if (d.createdAt) meta.push(`added ${formatDate(d.createdAt)}`);
    const chips = h(
      "div",
      { class: "chips", testid: "device-macs" },
      approvedOn.map((a) => h("span", { class: "chip", testid: "device-mac-chip", attrs: { "data-host-pub": a.hostPub }, text: app.macName(a.hostPub) })),
      pendingOn.map((a) => h("span", { class: "chip chip-pending", testid: "device-mac-chip", attrs: { "data-host-pub": a.hostPub, "data-pending": "1" }, text: `${app.macName(a.hostPub)} (waiting)` })),
    );
    chips.hidden = app.macs.length <= 1 || approvedOn.length + pendingOn.length === 0;
    const targets = app.revokableMacs(d);
    return h(
      "div",
      { class: "item", testid: "device-item", attrs: { "data-pub": d.pub, "data-status": approvedOn.length ? "approved" : pendingOn.length ? "pending" : "unknown", "data-mine": mine ? "1" : null } },
      h("span", { class: "item-icon" }, icon(kindIcon(d.kind))),
      h(
        "div",
        { class: "item-text" },
        h("strong", { testid: "device-name" }, d.name || "Unnamed device", mine ? h("span", { class: "tag", text: "This device" }) : null),
        h("span", { class: "muted", text: meta.join(" · ") }),
        chips,
      ),
      button({
        label: "Remove",
        testid: "device-remove",
        variant: "plain",
        disabled: app.signalState !== "ready" || targets.length === 0,
        onClick: async () => {
          const names = targets.map((m) => `“${m.name || "Mac"}”`).join(", ");
          const where = targets.length === 1 ? names : `these Macs: ${names}`;
          const ok = await confirmDialog({
            title: mine ? "Remove this device?" : `Remove “${d.name}”?`,
            text: mine
              ? `This device will no longer be able to connect to ${where} until it's approved again.`
              : `It will immediately lose access to ${where}. It would need to be approved again to reconnect.`,
            confirm: "Remove",
            danger: true,
            testid: "device-remove-confirm",
          });
          if (!ok) return;
          const n = await app.revokeDevice(d);
          toast(n === 1 ? `Asked ${names} to remove the device.` : `Asked ${n} Macs to remove the device.`, "success");
        },
      }),
    );
  }

  function renderDevices(): void {
    const devs = (app.me?.devices ?? []).filter((d) => d.pub === myPub || d.approvals.some((a) => (a.status === "approved" || a.status === "pending") && app.mac(a.hostPub)));
    devs.sort((a, b) => (a.pub === myPub ? -1 : b.pub === myPub ? 1 : a.name.localeCompare(b.name)));
    replace(devicesList, devs.length ? devs.map(deviceItem) : h("p", { class: "muted", text: "No devices yet." }));
    devicesCard.hidden = !approvedAnywhere();
  }

  // ---------------------------------------------------------- passkeys
  const passkeysList = h("div", { class: "list", testid: "passkeys-list" });
  const canAddPasskey = app.platform.kind === "browser" && webauthnAvailable();
  const passkeysCard = card(
    { testid: "passkeys", title: "Passkeys", icon: "key" },
    h("p", { class: "muted", text: "Passkeys let you sign in. Add one on a second device so you're never locked out." }),
    passkeysList,
    canAddPasskey ? button({ label: "Add a passkey", testid: "passkey-add", icon: "plus", onClick: addPasskey }) : null,
  );

  function passkeyItem(p: PasskeyInfo, count: number): HTMLElement {
    return h(
      "div",
      { class: "item", testid: "passkey-item", attrs: { "data-id": p.id } },
      h("span", { class: "item-icon" }, icon("key")),
      h(
        "div",
        { class: "item-text" },
        h("strong", { text: p.name || "Passkey" }),
        h("span", { class: "muted", text: p.createdAt ? `added ${formatDate(p.createdAt)}` : "" }),
      ),
      count > 1
        ? button({
            label: "Remove",
            testid: "passkey-remove",
            variant: "plain",
            onClick: async () => {
              const ok = await confirmDialog({
                title: "Remove this passkey?",
                text: "You won't be able to sign in with it any more. Your other passkeys keep working.",
                confirm: "Remove",
                danger: true,
                testid: "passkey-remove-confirm",
              });
              if (!ok) return;
              const proof = await app.deviceProof();
              await app.api.passkeysDelete(proof, p.id);
              await app.refreshMe();
              toast("Passkey removed.", "success");
            },
          })
        : null,
    );
  }

  function renderPasskeys(): void {
    const pks = app.me?.passkeys ?? [];
    replace(passkeysList, pks.length ? pks.map((p) => passkeyItem(p, pks.length)) : h("p", { class: "muted", text: "No passkeys found." }));
    passkeysCard.hidden = !approvedAnywhere();
  }

  async function addPasskey(): Promise<void> {
    const proof = await app.deviceProof();
    const flow = await app.api.passkeysBegin(proof);
    // Second step so the WebAuthn call happens directly inside a tap (Safari).
    const s = openSheet({
      title: "Add a passkey",
      testid: "passkey-sheet",
      content: [
        h("p", { class: "sheet-text", text: "Your browser will ask you to create a passkey. You can save it on this device, or choose “Use a phone or tablet” to save it on another one." }),
        h(
          "div",
          { class: "row-end" },
          button({
            label: "Create passkey",
            testid: "passkey-create",
            variant: "primary",
            icon: "key",
            onClick: async () => {
              const credential = await createPasskey(flow.options);
              const proof2 = await app.deviceProof();
              await app.api.passkeysFinish(proof2, flow.flowId, credential);
              s.close();
              await app.refreshMe();
              toast("Passkey added.", "success");
            },
          }),
        ),
      ],
    });
  }

  // ---------------------------------------------------------- footer
  const devFp = h("span", { testid: "device-fingerprint" });
  if (app.signer) void fingerprint(app.signer.pub).then((f) => (devFp.textContent = f));
  const footer = h("footer", { class: "fineprint home-footer" }, h("div", null, "This device's key: ", devFp));

  function showOfflineHelp(): void {
    openSheet({
      title: "Why is my Mac offline?",
      testid: "offline-help-sheet",
      content: [
        h("p", { class: "sheet-text", text: "A Mac shows as offline when it can't reach the server. Check these, in order:" }),
        h(
          "ol",
          { class: "steps" },
          h("li", { text: "Is the Mac asleep or turned off? Wake it up. To keep it available, in System Settings › Energy turn on “Prevent automatic sleeping when the display is off”." }),
          h("li", { text: "Is Heartfulness Remote running? Look for the heart in the menu bar. If it's missing, open it from Applications and turn on “Launch at login”." }),
          h("li", { text: "Is the Mac connected to the internet? Try opening a website on it." }),
          h("li", { text: "Did you just update macOS? Open Heartfulness Remote and check that Screen Recording and Accessibility are still allowed." }),
          h("li", { text: "Still offline? Restart the Mac. It reconnects automatically after you log in." }),
        ),
      ],
    });
  }

  // ---------------------------------------------------------- wiring
  const render = () => {
    renderMacs();
    renderApprovals();
    renderDevices();
    renderPasskeys();
  };
  offs.push(app.on("macs", render));
  offs.push(app.on("pins", render));
  offs.push(app.on("signal", render));
  offs.push(app.on("approvals", renderApprovals));
  offs.push(
    app.on("me", () => {
      renderDevices();
      renderPasskeys();
    }),
  );
  render();
  void app.refreshMeIfStale(3000);

  const el = page(
    "home",
    brand(button({ label: "Sign out", testid: "signout-button", variant: "plain", icon: "signout", onClick: () => app.signOut() })),
    heading,
    intro,
    approvalsCard,
    macsList,
    addMac,
    devicesCard,
    passkeysCard,
    footer,
  );

  return {
    name: "home",
    el,
    destroy() {
      for (const o of offs.splice(0)) o();
    },
  };
}
