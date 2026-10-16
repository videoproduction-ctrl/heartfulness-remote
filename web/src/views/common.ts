// Small shared views: page chrome, loading, errors and status messages.

import type { App, View } from "../app";
import { type Child, h } from "../dom";
import { type IconName, icon } from "../icons";
import { button, card, confirmDialog, errorMessage, spinner } from "../ui";
import { firstRunView } from "./firstrun";

export function brand(...right: Child[]): HTMLElement {
  return h(
    "header",
    { class: "topbar" },
    h("div", { class: "brand" }, h("span", { class: "brand-mark" }, icon("heart")), h("span", { class: "brand-name", text: "Heartfulness Remote" })),
    h("div", { class: "topbar-actions" }, ...right),
  );
}

export function page(name: string, ...children: Child[]): HTMLElement {
  return h("main", { class: `page page-${name}`, testid: `view-${name}` }, h("div", { class: "page-inner" }, ...children));
}

export function hero(iconName: IconName, title: string, subtitle?: string, tone = ""): HTMLElement {
  return h(
    "div",
    { class: `hero ${tone}`.trim() },
    h("div", { class: "hero-icon" }, icon(iconName)),
    h("h1", { text: title }),
    subtitle ? h("p", { class: "hero-sub", text: subtitle }) : null,
  );
}

export function loadingView(text: string): View {
  return {
    name: "loading",
    el: page("loading", brand(), h("div", { class: "center-block", testid: "loading" }, spinner(text), h("p", { class: "muted", text }))),
  };
}

export function errorView(app: App, e: unknown, retry: () => void): View {
  return {
    name: "error",
    el: page(
      "error",
      brand(),
      card(
        { testid: "error-card" },
        hero("warning", "Something went wrong", undefined, "tone-warn"),
        h("p", { class: "center", testid: "error-message", attrs: { "data-scope": "error-view", role: "alert" }, text: errorMessage(e) }),
        h("div", { class: "stack" }, button({ label: "Try again", testid: "error-retry", variant: "primary", large: true, onClick: retry })),
      ),
      app.platform.kind === "tauri"
        ? h(
            "p",
            { class: "center" },
            button({
              label: "Change server address",
              testid: "error-change-server",
              variant: "plain",
              onClick: () => app.show(firstRunView(app)),
            }),
          )
        : null,
    ),
  };
}

export function unsupportedView(reason: string): View {
  return {
    name: "unsupported",
    el: page("unsupported", brand(), card({ testid: "unsupported" }, hero("warning", "This browser can't be used", reason, "tone-warn"))),
  };
}

export function notSetUpView(app: App): View {
  return {
    name: "not-set-up",
    el: page(
      "not-set-up",
      brand(),
      card(
        { testid: "not-set-up" },
        hero("display", "Not set up yet", "Heartfulness Remote hasn't been connected to your Mac yet."),
        h(
          "ol",
          { class: "steps" },
          h("li", { text: "On your Mac, open Heartfulness Remote." }),
          h("li", { text: "It shows a QR code. Scan it with your phone's camera." }),
          h("li", { text: "Follow the steps on your phone to create your passkey." }),
        ),
        button({ label: "Check again", testid: "not-set-up-retry", onClick: () => void app.boot() }),
      ),
    ),
  };
}

export function revokedView(app: App): View {
  return {
    name: "revoked",
    el: page(
      "revoked",
      brand(button({ label: "Sign out", testid: "signout-button", variant: "plain", icon: "signout", onClick: () => app.signOut() })),
      card(
        { testid: "revoked" },
        hero("block", "This device was removed", "It can no longer connect to your Mac. If you want to use it again, ask for approval again.", "tone-warn"),
        button({
          label: "Ask for approval again",
          testid: "revoked-pair-again",
          variant: "primary",
          large: true,
          onClick: () => app.resetDevice(false),
        }),
      ),
    ),
  };
}

/** Approved by the server but this device has no pinned Mac key (e.g. browser data was cleared). */
export function missingPinView(app: App): View {
  return {
    name: "missing-pin",
    el: page(
      "missing-pin",
      brand(button({ label: "Sign out", testid: "signout-button", variant: "plain", icon: "signout", onClick: () => app.signOut() })),
      card(
        { testid: "missing-pin" },
        hero(
          "shield",
          "Please approve this device again",
          "This device no longer remembers your Mac's security key, so it can't make sure it's really talking to your Mac.",
          "tone-warn",
        ),
        button({
          label: "Ask for approval again",
          testid: "missing-pin-pair-again",
          variant: "primary",
          large: true,
          onClick: async () => {
            if (
              await confirmDialog({
                title: "Approve this device again?",
                text: "This device will get a new security key and must be approved again on your Mac or phone. Remove the old entry from your devices list afterwards.",
                confirm: "Continue",
                testid: "missing-pin-confirm",
              })
            ) {
              await app.resetDevice(false);
            }
          },
        }),
      ),
    ),
  };
}
