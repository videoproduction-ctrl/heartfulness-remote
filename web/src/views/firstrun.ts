// Tauri first run: ask for the server address (e.g. heartfulness-remote.dedyn.io).

import type { App, View } from "../app";
import { Api, type ServerStatus } from "../api";
import { h } from "../dom";
import { normalizeOrigin } from "../platform";
import { button, card, errorBox, setError } from "../ui";
import { brand, hero, page } from "./common";

export function firstRunView(app: App): View {
  const input = h("input", {
    class: "input",
    testid: "firstrun-origin-input",
    attrs: {
      type: "text",
      inputmode: "url",
      autocomplete: "url",
      autocapitalize: "off",
      spellcheck: "false",
      placeholder: "heartfulness-remote.dedyn.io",
      autofocus: true,
      "aria-label": "Server address",
    },
  });
  input.value = app.platform.origin()?.replace(/^https:\/\//, "") ?? "";
  const err = errorBox("firstrun");
  const save = button({
    label: "Continue",
    testid: "firstrun-save",
    variant: "primary",
    large: true,
    type: "submit",
  });

  const form = h(
    "form",
    { class: "stack", attrs: { novalidate: true } },
    h("label", { class: "label", attrs: { for: "server-input" }, text: "Your server address" }),
    input,
    h("p", { class: "hint", text: "This is the web address you use to connect, for example heartfulness-remote.dedyn.io." }),
    err,
    save,
  );
  input.id = "server-input";

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void (async () => {
      setError(err, null);
      save.disabled = true;
      try {
        const origin = normalizeOrigin(input.value);
        // Check that a Heartfulness Remote server answers there before saving.
        const probe = new Api({
          request: (path: string, method: "GET" | "POST") =>
            fetch(origin + path, {
              method,
              headers: { "X-HR": "1", Accept: "application/json" },
              credentials: "omit",
              mode: "cors",
              cache: "no-store",
              redirect: "error",
              signal: AbortSignal.timeout(15000),
            }),
        });
        let st: ServerStatus;
        try {
          st = await probe.status();
        } catch {
          throw new Error("No Heartfulness Remote server answered at that address. Check the spelling and your internet connection.");
        }
        if (typeof st.origin === "string" && st.origin !== "" && st.origin.replace(/\/$/, "") !== origin) {
          throw new Error(`That server calls itself ${st.origin}. Please enter exactly that address.`);
        }
        await app.platform.setOrigin(origin);
        await app.boot();
      } catch (ex) {
        setError(err, ex);
      } finally {
        save.disabled = false;
      }
    })();
  });

  return {
    name: "first-run",
    el: page("first-run", brand(), card({ testid: "first-run" }, hero("display", "Welcome", "Let's connect this app to your Heartfulness Remote server."), form)),
  };
}
