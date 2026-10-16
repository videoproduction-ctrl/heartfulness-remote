// Approve a desktop app sign-in (#link): the signed-in owner TYPES the code
// shown by the Heartfulness Remote app on their own computer.

import type { App, View } from "../app";
import { h, replace } from "../dom";
import { button, card, errorBox, setError } from "../ui";
import { brand, hero, page } from "./common";

/** "abcd efgh" / "ABCD-EFGH" / "abcdefgh" → "ABCD-EFGH" (or "" if not 8 code characters). */
export function normalizeLinkCode(s: string): string {
  const c = s.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return c.length === 8 ? `${c.slice(0, 4)}-${c.slice(4)}` : "";
}

export function linkApproveView(app: App): View {
  const err = errorBox("link-error");
  const input = h("input", {
    class: "input input-code",
    testid: "link-code-input",
    attrs: {
      type: "text",
      inputmode: "text",
      autocomplete: "off",
      autocapitalize: "characters",
      spellcheck: "false",
      maxlength: 9,
      placeholder: "ABCD-EFGH",
      autofocus: true,
      "aria-label": "Code shown in the app",
    },
  });
  input.id = "link-code-input";
  input.addEventListener("input", () => {
    const raw = input.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8);
    input.value = raw.length > 4 ? `${raw.slice(0, 4)}-${raw.slice(4)}` : raw;
  });

  const body = h("div", { class: "stack" });
  const submit = button({ label: "Approve sign-in", testid: "link-approve", variant: "primary", large: true, type: "submit" });
  const form = h(
    "form",
    { class: "stack", attrs: { novalidate: true } },
    h(
      "div",
      { class: "warning-box", testid: "link-warning", attrs: { role: "note" } },
      h("strong", { text: "Only enter a code shown on your own computer." }),
      h("span", { text: " Never type a code someone sent you or read to you — it would let them sign in as you." }),
    ),
    h("label", { class: "label", attrs: { for: "link-code-input" }, text: "Code shown in the Heartfulness Remote app" }),
    input,
    err,
    submit,
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void (async () => {
      setError(err, null);
      const code = normalizeLinkCode(input.value);
      if (!code) {
        setError(err, "The code has 8 letters and numbers, like ABCD-EFGH.");
        return;
      }
      submit.disabled = true;
      try {
        await app.api.linkApprove(code);
        replace(
          body,
          h("div", { class: "success-mark", testid: "link-done" }, h("span", { text: "✓" })),
          h("p", { class: "center", text: "Done. The app on your computer is now signed in. It still needs to be approved as a trusted device before it can connect." }),
          button({ label: "Back to Home", testid: "link-home", variant: "primary", onClick: () => app.goHome() }),
        );
      } catch (ex) {
        setError(err, ex);
      } finally {
        submit.disabled = false;
      }
    })();
  });
  replace(body, form, button({ label: "Cancel", testid: "link-cancel", variant: "plain", onClick: () => app.goHome() }));

  return {
    name: "link",
    el: page("link", brand(), card({ testid: "link-card" }, hero("laptop", "Sign in the desktop app", "Type the code that the Heartfulness Remote app shows on your computer."), body)),
  };
}
