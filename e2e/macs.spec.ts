// Multiple Macs per account (PROTOCOL.md §10), TeamViewer-style: each Mac shows
// a Mac ID; the owner adds it from a device they already use (typed Mac ID +
// code, or by scanning its QR link), and connects to any Mac they choose.
import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import { startStack, startMac, addPasskeyAuthenticator, copyPasskeys, waitFor, type Stack, type SimMac } from "./harness";

test.describe.configure({ mode: "serial" });

let stack: Stack;
let studio: SimMac;
let edit: SimMac;
type Dev = { ctx: BrowserContext; page: Page; auth: { cdp: any; id: string } };
let phone: Dev;
let laptop: Dev;
let lastPasskeyUser: Dev["auth"];

const formatId = (id: string) => `${id.slice(0, 3)} ${id.slice(3, 6)} ${id.slice(6)}`;
const card = (p: Page, macId: string) => p.locator(`[data-testid="mac-card"][data-mac-id="${macId}"]`);

async function dev(browser: any, viewport = { width: 1280, height: 800 }): Promise<Dev> {
  const ctx = await browser.newContext({ viewport, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  page.on("pageerror", (e: Error) => console.log(`[pageerror] ${e.message}`));
  return { ctx, page, auth: await addPasskeyAuthenticator(page) };
}

test.beforeAll(async ({ browser }) => {
  stack = await startStack(18686);
  phone = await dev(browser, { width: 390, height: 844 });
  await phone.page.goto(stack.hostState().setupURL);
  await phone.page.getByTestId("setup-device-name").fill("Owner's iPhone");
  await phone.page.getByTestId("setup-create-passkey").click();
  await expect(phone.page.getByTestId("macs-list")).toBeVisible();
  lastPasskeyUser = phone.auth;
});

test.afterAll(async () => {
  for (const d of [phone, laptop]) await d?.ctx.close().catch(() => {});
  await studio?.stop();
  await edit?.stop();
  await stack?.stop();
});

test("1. a second Mac shows its Mac ID and a join code (not yet in the account)", async () => {
  studio = await startMac(stack, "Studio Mac");
  const st = await waitFor(() => (studio.state().joinCode ? studio.state() : undefined), 15000, "join code");
  expect(st.joined).toBe(false);
  expect(st.macId).toMatch(/^\d{9}$/);
  expect(st.joinCode).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
  expect(st.joinURL).toContain("#join=");
  expect(st.setupURL ?? "").toBe("");
});

test("2. the phone adds it by typing the Mac ID and code", async () => {
  const st = studio.state();
  await phone.page.getByTestId("add-mac-button").click();
  await phone.page.getByTestId("add-mac-id-input").fill(formatId(st.macId));
  await phone.page.getByTestId("add-mac-code-input").fill(st.joinCode.toLowerCase().replace(/-/g, " "));
  await phone.page.getByTestId("add-mac-submit").click();
  await expect(phone.page.getByTestId("add-mac-done")).toBeVisible();
  await waitFor(() => studio.state().joined === true, 10000, "studio joined");
  expect(studio.state().devices.map((d: any) => d.name)).toContain("Owner's iPhone");
  expect(studio.state().joinCode ?? "").toBe("");
});

test("3. a third Mac is added by scanning its QR link on the phone", async () => {
  edit = await startMac(stack, "Edit Bay Mac");
  const st = await waitFor(() => (edit.state().joinURL ? edit.state() : undefined), 15000, "join url");
  await phone.page.goto(st.joinURL);
  await expect.poll(() => phone.page.url()).not.toContain("#join=");
  await expect(phone.page.getByTestId("add-mac-done")).toBeVisible();
  await waitFor(() => edit.state().joined === true, 10000, "edit joined");
});

test("4. the phone sees all three Macs, each with its own Mac ID and status", async () => {
  await phone.page.goto(stack.origin + "/");
  const cards = phone.page.getByTestId("mac-card");
  await expect(cards).toHaveCount(3);
  for (const m of [stack.hostState(), studio.state(), edit.state()]) {
    await expect(card(phone.page, m.macId)).toBeVisible();
    await expect(card(phone.page, m.macId).getByTestId("mac-id")).toHaveText(formatId(m.macId));
    await expect(card(phone.page, m.macId).getByTestId("mac-status-title")).toHaveText(/online/i);
  }
});

test("5. a laptop approved on the first Mac must ask for access to the Studio Mac; the phone approves", async ({ browser }) => {
  laptop = await dev(browser);
  await copyPasskeys(lastPasskeyUser, laptop.auth);
  lastPasskeyUser = laptop.auth;
  await laptop.page.goto(stack.origin + "/");
  await laptop.page.getByTestId("login-button").click();
  // Not approved anywhere yet: ask the Studio Mac for access.
  const studioCard = card(laptop.page, studio.state().macId);
  await expect(studioCard).toBeVisible();
  await studioCard.getByTestId("mac-ask-access").click();
  const name = laptop.page.getByTestId("pair-name-input");
  if (await name.isVisible().catch(() => false)) {
    await name.fill("Studio Laptop");
    await laptop.page.getByTestId("pair-start-button").click();
  }
  const sas = (await laptop.page.getByTestId("pair-sas").innerText()).replace(/\D/g, "");
  expect(sas).toMatch(/^\d{6}$/);
  const item = phone.page.getByTestId("approval-item");
  await expect(item).toBeVisible();
  await expect(phone.page.getByTestId("approval-sas")).toHaveText(new RegExp(sas.slice(0, 3) + "\\s?" + sas.slice(3)));
  await phone.page.getByTestId("approval-approve").click();
  await waitFor(() => studio.state().devices.some((d: any) => d.name === "Studio Laptop"), 10000, "laptop pinned on studio");
  // Only on the Studio Mac — the first Mac doesn't trust the laptop.
  expect(stack.hostState().devices.map((d: any) => d.name)).not.toContain("Studio Laptop");
});

test("6. the laptop connects to the Studio Mac (and only that Mac gets the session)", async () => {
  await laptop.page.goto(stack.origin + "/");
  const studioCard = card(laptop.page, studio.state().macId);
  await studioCard.getByTestId("mac-connect").click();
  await expect
    .poll(async () => laptop.page.evaluate(() => {
      const v = document.querySelector("video");
      return v ? v.videoWidth > 0 && v.currentTime > 0.5 : false;
    }), { timeout: 20_000 })
    .toBe(true);
  await waitFor(() => studio.state().session?.device?.name === "Studio Laptop", 10000, "studio session");
  expect(stack.hostState().session ?? null).toBeNull();
  expect(edit.state().session ?? null).toBeNull();
  // The phone shows "Someone connected" on the Studio Mac card only.
  await expect(card(phone.page, studio.state().macId).getByTestId("mac-status-title")).toHaveText(/someone connected/i);
  await expect(card(phone.page, edit.state().macId).getByTestId("mac-status-title")).toHaveText(/online/i);
  await laptop.page.getByTestId("disconnect-button").dispatchEvent("click");
  await waitFor(() => studio.state().session === null, 10000, "session ended");
});

test("7. the laptop cannot connect to a Mac that never approved it", async () => {
  await laptop.page.goto(stack.origin + "/");
  const editCard = card(laptop.page, edit.state().macId);
  await expect(editCard.getByTestId("mac-connect")).toHaveCount(0);
  await expect(editCard.getByTestId("mac-ask-access")).toBeVisible();
});

test("8. removing a Mac from the account hides it and the Mac shows a new join code", async () => {
  const id = edit.state().macId;
  const c = card(phone.page, id);
  await c.getByTestId("mac-menu").click();
  await phone.page.getByTestId("mac-remove").click();
  await phone.page.getByTestId("confirm-ok").click();
  await expect(card(phone.page, id)).toHaveCount(0);
  await waitFor(() => edit.state().joined === false && edit.state().joinCode, 15000, "new join code");
});
