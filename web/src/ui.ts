// Shared UI building blocks (buttons, cards, sheets, toasts).

import { type Child, append, h } from "./dom";
import { type IconName, icon } from "./icons";

export type Variant = "primary" | "secondary" | "danger" | "plain" | "tinted";

export interface ButtonOpts {
  label: string;
  testid: string;
  onClick?: (e: MouseEvent) => void | Promise<void>;
  variant?: Variant;
  icon?: IconName;
  disabled?: boolean;
  large?: boolean;
  type?: "button" | "submit";
  title?: string;
}

export function button(o: ButtonOpts): HTMLButtonElement {
  const cls = ["btn", `btn-${o.variant ?? "secondary"}`];
  if (o.large) cls.push("btn-large");
  const b = h(
    "button",
    {
      class: cls.join(" "),
      testid: o.testid,
      attrs: { type: o.type ?? "button", title: o.title },
    },
    o.icon ? icon(o.icon) : null,
    h("span", { class: "btn-label", text: o.label }),
  );
  b.disabled = !!o.disabled;
  if (o.onClick) {
    const fn = o.onClick;
    b.addEventListener("click", (e) => {
      if (b.disabled || b.getAttribute("aria-busy") === "true") return;
      const r = fn(e);
      if (r instanceof Promise) {
        setBusy(b, true);
        r.catch((err: unknown) => toast(errorMessage(err), "error")).finally(() => setBusy(b, false));
      }
    });
  }
  return b;
}

export function iconButton(name: IconName, label: string, testid: string, onClick: (e: MouseEvent) => void, cls = "icon-btn"): HTMLButtonElement {
  const b = h("button", { class: cls, testid, title: label, attrs: { type: "button", "aria-label": label } }, icon(name));
  b.addEventListener("click", onClick);
  return b;
}

export function setBusy(b: HTMLButtonElement, busy: boolean): void {
  b.setAttribute("aria-busy", busy ? "true" : "false");
  b.classList.toggle("is-busy", busy);
}

export function setLabel(b: HTMLButtonElement, label: string): void {
  const l = b.querySelector(".btn-label");
  if (l) l.textContent = label;
}

export function card(props: { class?: string; testid?: string; title?: string; icon?: IconName }, ...children: Child[]): HTMLElement {
  const c = h("section", { class: `card ${props.class ?? ""}`.trim(), testid: props.testid });
  if (props.title) {
    c.appendChild(h("h2", { class: "card-title" }, props.icon ? icon(props.icon) : null, h("span", { text: props.title })));
  }
  append(c, ...children);
  return c;
}

export function spinner(label = "Loading"): HTMLElement {
  return h("span", { class: "spinner", attrs: { role: "progressbar", "aria-label": label } });
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error && e.message) return e.message;
  return "Something went wrong. Please try again.";
}

/** The view's error line: data-testid="error-message", data-scope=<form>. */
export function errorBox(scope: string): HTMLParagraphElement {
  const p = h("p", { class: "error-box", testid: "error-message", attrs: { role: "alert", "data-scope": scope } });
  p.hidden = true;
  return p;
}

export function setError(p: HTMLElement, e: unknown | null): void {
  if (e === null || e === undefined || e === "") {
    p.hidden = true;
    p.textContent = "";
  } else {
    p.hidden = false;
    p.textContent = typeof e === "string" ? e : errorMessage(e);
  }
}

// ---------------------------------------------------------------- toasts

let toastRegion: HTMLElement | null = null;

export function toast(text: string, level: "info" | "error" | "success" = "info", ms = 4500): void {
  if (!toastRegion || !toastRegion.isConnected) {
    toastRegion = h("div", { class: "toasts", testid: "toasts", attrs: { "aria-live": "polite", role: "status" } });
    document.body.appendChild(toastRegion);
  }
  const t = h("div", { class: `toast toast-${level}`, testid: "toast", text, attrs: { "data-level": level } });
  toastRegion.appendChild(t);
  setTimeout(() => {
    t.classList.add("toast-out");
    setTimeout(() => t.remove(), 300);
  }, ms);
}

// ---------------------------------------------------------------- sheets (modal dialogs)

export interface Sheet {
  dialog: HTMLDialogElement;
  body: HTMLElement;
  close(): void;
}

export function openSheet(o: { title: string; testid: string; content?: Child; onClose?: () => void; wide?: boolean; side?: boolean }): Sheet {
  const body = h("div", { class: "sheet-body" });
  append(body, o.content);
  const closeBtn = iconButton("close", "Close", `${o.testid}-close`, () => close());
  const dialog = h(
    "dialog",
    { class: `sheet${o.wide ? " sheet-wide" : ""}${o.side ? " sheet-side" : ""}`, testid: o.testid, attrs: { "aria-label": o.title } },
    h("header", { class: "sheet-header" }, h("h2", { text: o.title }), closeBtn),
    body,
  );
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    if (dialog.open) dialog.close();
    dialog.remove();
    o.onClose?.();
  };
  dialog.addEventListener("close", close);
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) close(); // click on the backdrop
  });
  document.body.appendChild(dialog);
  dialog.showModal();
  return { dialog, body, close };
}

export function confirmDialog(o: { title: string; text: string; confirm: string; danger?: boolean; testid?: string }): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let result = false;
    const tid = o.testid ?? "confirm";
    const s = openSheet({
      title: o.title,
      testid: tid,
      onClose: () => resolve(result),
      content: [
        h("p", { class: "sheet-text", text: o.text }),
        h(
          "div",
          { class: "row-end" },
          // Generic ids: only one confirmation is ever open; the dialog itself
          // carries the specific id (e.g. "block-confirm").
          button({ label: "Cancel", testid: "confirm-cancel", onClick: () => s.close() }),
          button({
            label: o.confirm,
            testid: "confirm-ok",
            variant: o.danger ? "danger" : "primary",
            onClick: () => {
              result = true;
              s.close();
            },
          }),
        ),
      ],
    });
  });
}

export function formatDate(v: unknown): string {
  let d: Date | null = null;
  if (typeof v === "number" && Number.isFinite(v)) d = new Date(v < 1e12 ? v * 1000 : v);
  else if (typeof v === "string" && v !== "") d = new Date(v);
  if (!d || Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function formatRelative(v: unknown): string {
  let ms: number | null = null;
  if (typeof v === "number" && Number.isFinite(v)) ms = v < 1e12 ? v * 1000 : v;
  else if (typeof v === "string" && v !== "") ms = new Date(v).getTime();
  if (ms === null || Number.isNaN(ms) || ms <= 0) return "";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return formatDate(v);
}
