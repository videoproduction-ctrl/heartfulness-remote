// Screenshot tour of the multi-Mac interface: three simulated Macs, a phone
// (light) and a laptop (dark).   cd e2e && node demo/tour-macs.ts
import { chromium, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { startStack, startMac, addPasskeyAuthenticator, copyPasskeys, waitFor } from "../harness.ts";

const OUT = join(import.meta.dirname, "out", "tour-macs");
mkdirSync(OUT, { recursive: true });
const stack = await startStack(18787);
const browser = await chromium.launch({ args: ["--disable-features=WebRtcHideLocalIpsWithMdns", "--autoplay-policy=no-user-gesture-required"] });
const mk = async (viewport: { width: number; height: number }, colorScheme: "light" | "dark", scale = 2) => {
  const ctx = await browser.newContext({ viewport, colorScheme, deviceScaleFactor: scale, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  return { ctx, page, auth: await addPasskeyAuthenticator(page) };
};
const shot = async (p: Page, name: string, full = false) => {
  await p.waitForTimeout(700);
  await p.screenshot({ path: join(OUT, name + ".png"), fullPage: full });
  console.log("shot", name);
};
const fmt = (id: string) => `${id.slice(0, 3)} ${id.slice(3, 6)} ${id.slice(6)}`;

const phone = await mk({ width: 390, height: 844 }, "light");
await phone.page.goto(stack.hostState().setupURL);
await phone.page.getByTestId("setup-device-name").fill("My iPhone");
await phone.page.getByTestId("setup-create-passkey").click();
await phone.page.getByTestId("macs-list").waitFor();

const studio = await startMac(stack, "Studio Mac");
const edit = await startMac(stack, "Edit Bay Mac");
await waitFor(() => studio.state().joinCode && edit.state().joinURL, 15000, "codes");

// Add the Studio Mac by typing its Mac ID + code.
await phone.page.getByTestId("add-mac-button").click();
await phone.page.getByTestId("add-mac-id-input").fill(fmt(studio.state().macId));
await phone.page.getByTestId("add-mac-code-input").fill(studio.state().joinCode);
await shot(phone.page, "01-phone-add-a-mac");
await phone.page.getByTestId("add-mac-submit").click();
await phone.page.getByTestId("add-mac-done").waitFor();
await shot(phone.page, "02-phone-mac-added");

// Add the Edit Bay Mac by its QR link (with the confirmation step).
await phone.page.goto(edit.state().joinURL);
await phone.page.getByTestId("add-mac-submit").waitFor();
await shot(phone.page, "03-phone-confirm-qr-mac");
await phone.page.getByTestId("add-mac-submit").click();
await phone.page.getByTestId("add-mac-done").waitFor();
await phone.page.goto(stack.origin + "/");
await phone.page.getByTestId("mac-card").nth(2).waitFor();
await shot(phone.page, "04-phone-your-macs", true);

// A laptop asks the Studio Mac for access; the phone approves.
const laptop = await mk({ width: 1280, height: 800 }, "dark", 1.5);
await copyPasskeys(phone.auth, laptop.auth);
await laptop.page.goto(stack.origin + "/");
await laptop.page.getByTestId("login-button").click();
const studioCard = laptop.page.locator(`[data-testid="mac-card"][data-mac-id="${studio.state().macId}"]`);
await studioCard.waitFor();
await shot(laptop.page, "05-laptop-your-macs");
await studioCard.getByTestId("mac-ask-access").click();
const nameInput = laptop.page.getByTestId("pair-name-input");
if (await nameInput.isVisible().catch(() => false)) {
  await nameInput.fill("Studio Laptop");
  await laptop.page.getByTestId("pair-start-button").click();
}
await laptop.page.getByTestId("pair-sas").waitFor();
await phone.page.getByTestId("approval-item").waitFor();
await shot(phone.page, "06-phone-approve-for-studio-mac");
await phone.page.getByTestId("approval-approve").click();
await waitFor(() => studio.state().devices?.some((d: any) => d.name === "Studio Laptop"), 10000, "approved");
await laptop.page.goto(stack.origin + "/");
await studioCard.getByTestId("mac-connect").waitFor();
await studioCard.getByTestId("mac-connect").click();
await waitFor(() => studio.state().session, 20000, "session");
await laptop.page.waitForTimeout(2500);
await laptop.page.mouse.move(640, 10);
await shot(laptop.page, "07-laptop-connected-to-studio-mac");
await phone.page.reload();
await phone.page.getByTestId("mac-card").nth(2).waitFor();
await shot(phone.page, "08-phone-studio-mac-in-use", true);

await browser.close();
await studio.stop();
await edit.stop();
await stack.stop();
