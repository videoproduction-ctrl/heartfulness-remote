// Home: big status card, Connect, approvals inbox, kill switch, devices and passkeys.

import type { App, Approval, View } from "../app";
import type { DeviceInfo, PasskeyInfo } from "../api";
import { b64 } from "../b64";
import { h, replace } from "../dom";
import { fingerprint, formatSAS } from "../hr1";
import { type IconName, icon } from "../icons";
import { button, card, confirmDialog, formatDate, formatRelative, openSheet, toast } from "../ui";
import { createPasskey, webauthnAvailable } from "../webauthn";
import { brand, page } from "./common";

type StatusKind = "online" | "offline" | "busy" | "blocked" | "checking" | "warning";

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

export function homeView(app: App): View {
  const offs: Array<() => void> = [];
  const myPub = app.signer ? b64(app.signer.pub) : "";

  // ---------------------------------------------------------- status card
  const dot = h("span", { class: "status-dot", attrs: { "aria-hidden": "true" } });
  const title = h("h1", { class: "status-title", testid: "home-status-title" });
  const detail = h("p", { class: "status-detail", testid: "home-status-detail" });
  const macName = h("p", { class: "status-mac", testid: "home-mac-name" });
  const helpLink = h("button", { class: "link-btn", testid: "offline-help", text: "Why offline?", attrs: { type: "button" } });
  helpLink.addEventListener("click", showOfflineHelp);
  const connect = button({ label: "Connect", testid: "connect-button", variant: "primary", large: true, icon: "display", onClick: () => app.goSession() });
  const warning = h("div", { class: "warning-box", testid: "host-mismatch", attrs: { role: "alert" } });
  warning.hidden = true;
  const statusCard = h(
    "section",
    { class: "card status-card", testid: "home-status", attrs: { "aria-live": "polite" } },
    h("div", { class: "status-head" }, dot, h("div", { class: "status-text", testid: "home-status-text" }, title, detail)),
    macName,
    helpLink,
    connect,
  );

  function renderStatus(): void {
    const hst = app.host;
    let kind: StatusKind;
    let t: string;
    let d: string;
    const sigState = app.signalState;
    if (app.hostMismatch) {
      kind = "warning";
      t = "Security warning";
      d = "The server is presenting a different Mac than the one this device trusts. Connecting is disabled.";
    } else if (sigState !== "ready" || !hst) {
      kind = "checking";
      t = "Checking…";
      d = sigState === "reconnecting" ? "Reconnecting to the server…" : "Contacting the server…";
    } else if (!hst.online) {
      kind = "offline";
      t = "Offline";
      d = "Your Mac isn't reachable right now.";
    } else if (hst.state === "blocked") {
      kind = "blocked";
      t = "Blocked";
      d = "All connections are blocked. Choose “Allow connections” below to use your Mac again.";
    } else if (hst.state === "in-session") {
      kind = "busy";
      t = "Someone connected";
      d = hst.sessionDeviceName ? `${hst.sessionDeviceName} is using your Mac.` : "Another device is using your Mac.";
    } else {
      kind = "online";
      t = "Online";
      d = "Your Mac is ready.";
    }
    statusCard.dataset["state"] = kind;
    title.textContent = t;
    detail.textContent = d;
    macName.textContent = hst?.name ? hst.name : "";
    macName.hidden = !hst?.name;
    helpLink.hidden = kind !== "offline";
    connect.disabled = !(kind === "online" || kind === "busy");
    warning.hidden = !app.hostMismatch;
    if (app.hostMismatch) {
      replace(
        warning,
        h("strong", { text: "Security warning. " }),
        "Your server reports a different Mac key than the one this device trusts. If you didn't reinstall Heartfulness Remote on your Mac, someone may be trying to impersonate it. ",
        button({
          label: "I reinstalled my Mac",
          testid: "host-mismatch-reset",
          variant: "plain",
          onClick: async () => {
            if (
              await confirmDialog({
                title: "Trust a new Mac?",
                text: "Only do this if you reinstalled Heartfulness Remote on your Mac. This device will need to be approved again.",
                confirm: "Approve again",
                danger: true,
                testid: "host-mismatch-confirm",
              })
            ) {
              await app.resetDevice(true);
            }
          },
        }),
      );
    }
    renderControls();
  }

  // ---------------------------------------------------------- approvals
  const approvalsList = h("div", { class: "list", testid: "approvals-list" });
  const approvalsCard = card({ class: "approvals-card", testid: "approvals", title: "Approval needed", icon: "shield" }, approvalsList);

  function approvalItem(a: Approval): HTMLElement {
    const head = h(
      "div",
      { class: "item-head" },
      h("span", { class: "item-icon" }, icon(kindIcon(a.req.kind))),
      h(
        "div",
        { class: "item-text" },
        h("strong", { testid: "approval-name", text: a.req.name || "Unnamed device" }),
        h("span", { class: "muted", testid: "approval-kind", text: `${kindLabel(a.req.kind)} wants to connect to your Mac` }),
      ),
    );
    const item = h(
      "div",
      { class: "approval-item", testid: "approval-item", attrs: { "data-request-id": a.key, "data-state": a.error || !a.sas ? "invalid" : a.state } },
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
      item.appendChild(h("p", { class: "status-line", testid: "approval-sent", text: "Approved. Waiting for your Mac to confirm…" }));
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

  // ---------------------------------------------------------- kill switch
  const controlsBody = h("div", { class: "stack" });
  const controlsCard = card({ testid: "controls", title: "Security", icon: "lock" }, controlsBody);

  function renderControls(): void {
    const blocked = app.host?.state === "blocked";
    const usable = app.signalState === "ready" && !!app.pinned && !app.hostMismatch;
    replace(
      controlsBody,
      blocked
        ? [
            h("p", { class: "muted", text: "Your Mac is refusing all connections." }),
            button({
              label: "Allow connections",
              testid: "allow-button",
              variant: "primary",
              icon: "play",
              disabled: !usable,
              onClick: async () => {
                await app.killSwitch("resume");
                toast("Asked your Mac to allow connections again.", "success");
              },
            }),
          ]
        : [
            h("p", { class: "muted", text: "Instantly end any session and refuse new ones until you allow them again." }),
            button({
              label: "Block all connections",
              testid: "block-button",
              variant: "danger",
              icon: "block",
              disabled: !usable,
              onClick: async () => {
                if (
                  await confirmDialog({
                    title: "Block all connections?",
                    text: "Any current session ends immediately, and no device can connect until you choose “Allow connections” here or on your Mac.",
                    confirm: "Block",
                    danger: true,
                    testid: "block-confirm",
                  })
                ) {
                  await app.killSwitch("kill");
                  toast("Asked your Mac to block all connections.", "success");
                }
              },
            }),
          ],
    );
  }

  // ---------------------------------------------------------- devices
  const devicesList = h("div", { class: "list", testid: "devices-list" });
  const devicesCard = card({ testid: "devices", title: "Trusted devices", icon: "display" }, devicesList);

  function deviceItem(d: DeviceInfo): HTMLElement {
    const mine = d.pub === myPub;
    const meta: string[] = [kindLabel(d.kind)];
    if (d.status === "pending") meta.push("waiting for approval");
    else if (d.lastSeen) meta.push(`last used ${formatRelative(d.lastSeen)}`);
    else if (d.createdAt) meta.push(`added ${formatDate(d.createdAt)}`);
    return h(
      "div",
      { class: "item", testid: "device-item", attrs: { "data-pub": d.pub, "data-status": d.status, "data-mine": mine ? "1" : null } },
      h("span", { class: "item-icon" }, icon(kindIcon(d.kind))),
      h(
        "div",
        { class: "item-text" },
        h("strong", { testid: "device-name" }, d.name || "Unnamed device", mine ? h("span", { class: "tag", text: "This device" }) : null),
        h("span", { class: "muted", text: meta.join(" · ") }),
      ),
      button({
        label: "Remove",
        testid: "device-remove",
        variant: "plain",
        disabled: app.signalState !== "ready" || !app.pinned,
        onClick: async () => {
          const ok = await confirmDialog({
            title: mine ? "Remove this device?" : `Remove “${d.name}”?`,
            text: mine
              ? "This device will no longer be able to connect to your Mac until it's approved again."
              : "It will immediately lose access to your Mac. It would need to be approved again to reconnect.",
            confirm: "Remove",
            danger: true,
            testid: "device-remove-confirm",
          });
          if (!ok) return;
          await app.revokeDevice(d.pub);
          toast("Asked your Mac to remove the device.", "success");
        },
      }),
    );
  }

  function renderDevices(): void {
    const devs = (app.me?.devices ?? []).filter((d) => d.status !== "revoked");
    devs.sort((a, b) => (a.pub === myPub ? -1 : b.pub === myPub ? 1 : a.name.localeCompare(b.name)));
    replace(devicesList, devs.length ? devs.map(deviceItem) : h("p", { class: "muted", text: "No devices yet." }));
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
              const proof = await deviceProof();
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
  }

  async function deviceProof() {
    const origin = app.platform.origin();
    if (!app.signer || !origin) throw new Error("This device's key is not available.");
    return app.api.deviceProof(app.signer, origin);
  }

  async function addPasskey(): Promise<void> {
    const proof = await deviceProof();
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
              const proof2 = await deviceProof();
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
  const macFp = h("span", { testid: "mac-fingerprint" });
  const devFp = h("span", { testid: "device-fingerprint" });
  if (app.pinned) void fingerprint(app.pinned).then((f) => (macFp.textContent = f));
  if (app.signer) void fingerprint(app.signer.pub).then((f) => (devFp.textContent = f));
  const footer = h(
    "footer",
    { class: "fineprint home-footer" },
    h("div", null, "Mac security key: ", macFp),
    h("div", null, "This device's key: ", devFp),
  );

  function showOfflineHelp(): void {
    openSheet({
      title: "Why is my Mac offline?",
      testid: "offline-help-sheet",
      content: [
        h("p", { class: "sheet-text", text: "Your Mac shows as offline when it can't reach the server. Check these, in order:" }),
        h(
          "ol",
          { class: "steps" },
          h("li", { text: "Is your Mac asleep or turned off? Wake it up. To keep it available, in System Settings › Energy turn on “Prevent automatic sleeping when the display is off”." }),
          h("li", { text: "Is Heartfulness Remote running? Look for the heart in the menu bar. If it's missing, open it from Applications and turn on “Launch at login”." }),
          h("li", { text: "Is your Mac connected to the internet? Try opening a website on it." }),
          h("li", { text: "Did you just update macOS? Open Heartfulness Remote and check that Screen Recording and Accessibility are still allowed." }),
          h("li", { text: "Still offline? Restart your Mac. It reconnects automatically after you log in." }),
        ),
      ],
    });
  }

  // ---------------------------------------------------------- wiring
  const render = () => {
    renderStatus();
    renderApprovals();
    renderDevices();
    renderPasskeys();
  };
  offs.push(app.on("host", renderStatus));
  offs.push(app.on("signal", render));
  offs.push(app.on("approvals", renderApprovals));
  offs.push(
    app.on("me", () => {
      renderDevices();
      renderPasskeys();
    }),
  );
  render();
  void app.refreshMe();

  const el = page(
    "home",
    brand(button({ label: "Sign out", testid: "signout-button", variant: "plain", icon: "signout", onClick: () => app.signOut() })),
    warning,
    statusCard,
    approvalsCard,
    controlsCard,
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
