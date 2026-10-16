// Sign in. Browser: one passkey button (discoverable credential, user
// verification required). Tauri app: the "link" flow — the app shows a code,
// the owner types it into a browser where they're signed in with a passkey.

import type { App, View } from "../app";
import { ApiError, type Flow } from "../api";
import { defaultDeviceName } from "../device-name";
import { h, replace } from "../dom";
import { button, card, errorBox, setError, spinner } from "../ui";
import { getPasskey, webauthnAvailable } from "../webauthn";
import { brand, hero, page } from "./common";
import { firstRunView } from "./firstrun";

// The server's link/poll bucket refills one token every 6 s (burst 10).
const POLL_MS = 3000;
const POLL_BACKOFF_MS = 6500;

export function loginView(app: App): View {
  return app.platform.kind === "tauri" ? linkLoginView(app) : passkeyLoginView(app);
}

function passkeyLoginView(app: App): View {
  let destroyed = false;
  let flow: Flow | null = null;
  let loading: Promise<void> | null = null;
  const err = errorBox("login");

  const prepare = (): Promise<void> => {
    loading = app.api
      .loginBegin()
      .then((f) => {
        flow = f;
        btn.disabled = false;
      })
      .catch((e: unknown) => {
        flow = null;
        if (!destroyed) setError(err, e);
        btn.disabled = false;
      });
    return loading;
  };

  const btn = button({
    label: "Sign in with passkey",
    testid: "login-button",
    variant: "primary",
    large: true,
    icon: "key",
    disabled: true,
    onClick: async () => {
      setError(err, null);
      if (!flow) {
        await (loading ?? prepare());
        if (!flow) await prepare();
        if (!flow) return;
      }
      const f = flow;
      flow = null; // challenges are single-use
      try {
        const credential = await getPasskey(f.options);
        await app.api.loginFinish(f.flowId, credential);
      } catch (e) {
        setError(err, e);
        void prepare();
        return;
      }
      await app.boot();
    },
  });

  if (!webauthnAvailable()) {
    setError(err, "This browser doesn't support passkeys. Please use a recent Safari, Chrome, Edge or Firefox.");
  } else {
    void prepare();
  }

  return {
    name: "login",
    el: page(
      "login",
      brand(),
      card(
        { testid: "login-card" },
        hero("lock", "Sign in", "Use your passkey (Face ID, Touch ID, Windows Hello or your phone) to sign in. There are no passwords."),
        err,
        h("div", { class: "stack" }, btn),
      ),
      h("p", { class: "fineprint center", text: "First time here? Open Heartfulness Remote on your Mac and scan the setup QR code with your phone." }),
    ),
    destroy() {
      destroyed = true;
    },
  };
}

function linkLoginView(app: App): View {
  let destroyed = false;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  const err = errorBox("login");
  const body = h("div", { class: "stack" });
  const origin = app.platform.origin() ?? "";

  const stop = () => {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
  };

  const showStart = () => {
    stop();
    replace(
      body,
      button({ label: "Sign in", testid: "login-button", variant: "primary", large: true, icon: "key", onClick: start }),
      h("p", { class: "hint center", text: `Server: ${origin}` }),
      button({
        label: "Change server address",
        testid: "change-server",
        variant: "plain",
        onClick: () => app.show(firstRunView(app)),
      }),
    );
  };

  async function start(): Promise<void> {
    setError(err, null);
    const name = defaultDeviceName({ userAgent: navigator.userAgent, maxTouchPoints: navigator.maxTouchPoints, app: true });
    const r = await app.api.linkStart(name);
    if (destroyed) return;
    const codeEl = h("div", { class: "link-code", testid: "link-code", text: r.code, attrs: { "aria-label": `Code ${r.code.split("").join(" ")}` } });
    const openBrowser = () => app.platform.openURL(`${origin}/#link`);
    replace(
      body,
      h("p", { class: "center", text: "Your browser is opening. Sign in there with your passkey, then type this code:" }),
      codeEl,
      h("p", { class: "status-line", testid: "link-status" }, spinner("Waiting"), " Waiting for you to enter the code…"),
      button({ label: "Open browser again", testid: "link-open-browser", icon: "forward", onClick: openBrowser }),
      button({ label: "Cancel", testid: "link-cancel", variant: "plain", onClick: showStart }),
    );
    await openBrowser().catch(() => undefined);
    const deadline = Date.now() + Math.max(30, Math.min(r.expiresIn || 600, 900)) * 1000;
    const poll = async () => {
      pollTimer = null;
      if (destroyed) return;
      if (Date.now() > deadline) {
        setError(err, "The code expired. Please try again.");
        showStart();
        return;
      }
      try {
        const p = await app.api.linkPoll(r.pollToken);
        if (destroyed) return;
        if (p.status === "approved" && typeof p.token === "string" && p.token !== "") {
          await app.platform.setToken(p.token);
          await app.boot();
          return;
        }
        if (p.status === "expired") {
          setError(err, "The code expired. Please try again.");
          showStart();
          return;
        }
        delay = POLL_MS;
      } catch (e) {
        // Transient error: keep polling until the deadline. The server allows
        // ~10 polls a minute, so back off when it says "too many".
        delay = e instanceof ApiError && e.status === 429 ? Math.max(POLL_BACKOFF_MS, (e.retryAfter ?? 0) * 1000) : POLL_MS;
      }
      pollTimer = setTimeout(() => void poll(), delay);
    };
    let delay = POLL_MS;
    pollTimer = setTimeout(() => void poll(), delay);
  }

  showStart();

  return {
    name: "login",
    el: page(
      "login",
      brand(),
      card(
        { testid: "login-card" },
        hero("lock", "Sign in", "You'll confirm this app from a browser where you use your passkey. No passwords."),
        err,
        body,
      ),
    ),
    destroy() {
      destroyed = true;
      stop();
    },
  };
}
