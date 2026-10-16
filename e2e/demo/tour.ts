// Screenshot tour of the real interface (real server + host agent core +
// Chromium): phone in light mode, computer in dark mode.
//   cd e2e && node demo/tour.ts   → e2e/demo/out/tour/*.png
import { chromium, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { startStack, addPasskeyAuthenticator, copyPasskeys, waitFor } from "../harness.ts";

const OUT = join(import.meta.dirname, "out", "tour");
mkdirSync(OUT, { recursive: true });
const stack = await startStack(18585);
const browser = await chromium.launch({
  args: ["--disable-features=WebRtcHideLocalIpsWithMdns", "--autoplay-policy=no-user-gesture-required"],
});
const mk = async (viewport: { width: number; height: number }, colorScheme: "light" | "dark", scale = 2) => {
  const ctx = await browser.newContext({ viewport, colorScheme, deviceScaleFactor: scale, reducedMotion: "reduce" });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: stack.origin });
  const page = await ctx.newPage();
  return { ctx, page, auth: await addPasskeyAuthenticator(page) };
};
const shot = async (p: Page, name: string) => {
  await p.waitForTimeout(600);
  await p.screenshot({ path: join(OUT, name + ".png") });
  console.log("shot", name);
};

const phone = await mk({ width: 390, height: 844 }, "light");
const mac = await mk({ width: 1280, height: 800 }, "dark", 1.5);

// 1. Phone opens the Mac's setup link.
await phone.page.goto(stack.hostState().setupURL);
await phone.page.getByTestId("setup-device-name").fill("My iPhone");
await shot(phone.page, "01-phone-setup");
await phone.page.getByTestId("setup-create-passkey").click();
await phone.page.getByTestId("home-status").waitFor();
await shot(phone.page, "02-phone-home-online");

// 2. A computer signs in and asks to be approved.
await copyPasskeys(phone.auth, mac.auth);
await mac.page.goto(stack.origin + "/");
await mac.page.getByTestId("login-button").waitFor();
await shot(mac.page, "03-computer-sign-in");
await mac.page.getByTestId("login-button").click();
await mac.page.getByTestId("pair-name-input").fill("Studio Laptop");
await mac.page.getByTestId("pair-start-button").click();
await mac.page.getByTestId("pair-sas").waitFor();
await shot(mac.page, "04-computer-approval-code");
await phone.page.getByTestId("approval-item").waitFor();
await shot(phone.page, "05-phone-approve-request");
await phone.page.getByTestId("approval-approve").click();
await mac.page.getByTestId("connect-button").waitFor();
await shot(mac.page, "06-computer-home");

// 3. Live session.
await mac.page.getByTestId("connect-button").click();
await waitFor(() => stack.hostState().session, 20000, "session");
await mac.page.waitForTimeout(2500);
await mac.page.mouse.move(640, 10);
await mac.page.waitForTimeout(300);
await shot(mac.page, "07-computer-session-toolbar");
await mac.page.getByTestId("files-button").dispatchEvent("click");
await mac.page.getByTestId("files-panel").waitFor();
await mac.page.getByTestId("file-entry").filter({ hasText: "Projects" }).first().click();
await mac.page.getByTestId("file-entry").filter({ hasText: "edit-notes.txt" }).first().waitFor();
await shot(mac.page, "08-computer-files");
await mac.page.keyboard.press("Escape");
await mac.page.getByTestId("toolbar-help").dispatchEvent("click");
await mac.page.getByTestId("help-sheet").waitFor();
await shot(mac.page, "09-computer-shortcuts");
await mac.page.keyboard.press("Escape");
await phone.page.reload();
await phone.page.getByTestId("home-status").waitFor();
await shot(phone.page, "10-phone-someone-connected");

// 4. Kill switch from the phone.
await phone.page.getByTestId("block-button").click();
await phone.page.getByTestId("confirm-ok").waitFor();
await shot(phone.page, "11-phone-block-confirm");
await phone.page.getByTestId("confirm-ok").click();
await waitFor(() => stack.hostState().killed, 10000, "killed");
await mac.page.waitForTimeout(1500);
await shot(mac.page, "12-computer-session-ended");
await phone.page.waitForTimeout(1000);
await shot(phone.page, "13-phone-blocked");
await phone.page.getByTestId("allow-button").click();

await browser.close();
await stack.stop();
