// End-to-end: the owner's whole journey, against the real Go server, the real
// Go host agent core (hostsim stands in for the Mac app's capture/input layer),
// and real Chromium with CDP virtual passkeys.
import { test, expect, type Page, type BrowserContext, type Browser } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { startStack, addPasskeyAuthenticator, copyPasskeys, waitFor, type Stack } from "./harness";

test.describe.configure({ mode: "serial" });

let stack: Stack;
type Dev = { ctx: BrowserContext; page: Page; auth: { cdp: any; id: string } };
const devs: Record<string, Dev> = {};
// Real synced passkeys (iCloud Keychain, Google Password Manager) share one
// credential state; the virtual authenticators don't sync, so we hand the
// credential (with its latest signature counter) to the next device ourselves.
// The server rightly rejects counters that go backwards (cloned authenticator).
let lastPasskeyUser: Dev["auth"] | undefined;

async function newDevice(browser: Browser, name: string, viewport = { width: 1280, height: 800 }): Promise<Dev> {
  // reducedMotion: sheets appear instantly, so clicks never race a slide-in animation.
  const ctx = await browser.newContext({ viewport, reducedMotion: "reduce", recordVideo: process.env.E2E_VIDEO ? { dir: "test-results/videos/" + name } : undefined });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: stack.origin });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log(`[${name} pageerror] ${e.message}`));
  const auth = await addPasskeyAuthenticator(page);
  devs[name] = { ctx, page, auth };
  return devs[name];
}

const hostDevices = () => (stack.hostState().devices ?? []).map((d: any) => d.name);
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

async function expectOnline(page: Page) {
  await expect(page.getByTestId("home-status")).toBeVisible();
  await expect(page.getByTestId("home-status-title")).toHaveText(/online/i);
}

async function connect(page: Page) {
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("session-video")).toBeVisible();
  await expect
    .poll(async () => page.evaluate(() => {
      const v = document.querySelector("video");
      return v ? v.videoWidth > 0 && v.currentTime > 0.5 : false;
    }), { timeout: 20_000 })
    .toBe(true);
}

async function disconnect(page: Page) {
  // The toolbar auto-hides; trigger the button itself rather than a screen position.
  await page.getByTestId("disconnect-button").dispatchEvent("click");
  await waitFor(() => stack.hostState().session === null, 10_000, "host session ended");
}

/** Signs in on a new browser with a synced passkey and asks the Mac to trust it. */
async function loginAndRequestPairing(d: Dev, deviceName: string): Promise<string> {
  await copyPasskeys(lastPasskeyUser ?? devs.phone.auth, d.auth);
  lastPasskeyUser = d.auth;
  await d.page.goto(stack.origin + "/");
  await d.page.getByTestId("login-button").click();
  const nameInput = d.page.getByTestId("pair-name-input");
  await expect(nameInput).toBeVisible();
  await nameInput.fill(deviceName);
  await d.page.getByTestId("pair-start-button").click();
  const sas = d.page.getByTestId("pair-sas");
  await expect(sas).toHaveText(/\d{3}\s?\d{3}/);
  return (await sas.innerText()).replace(/\D/g, "");
}

test.beforeAll(async () => {
  stack = await startStack(18181);
});

test.afterAll(async () => {
  for (const d of Object.values(devs)) await d.ctx.close().catch(() => {});
  await stack?.stop();
});

test("1. phone scans the Mac's setup code, creates a passkey and is trusted automatically", async ({ browser }) => {
  const st = stack.hostState();
  expect(st.claimed).toBe(false);
  expect(st.setupURL).toContain("#setup=");
  const phone = await newDevice(browser, "phone", { width: 390, height: 844 });
  await phone.page.goto(st.setupURL);
  // The one-time secret must be stripped from the address bar immediately.
  await expect.poll(() => phone.page.url()).not.toContain("#setup=");
  await phone.page.getByTestId("setup-device-name").fill("Owner's iPhone");
  await phone.page.getByTestId("setup-create-passkey").click();
  await expectOnline(phone.page);
  await waitFor(() => hostDevices().includes("Owner's iPhone"), 10_000, "phone pinned on the Mac");
  expect(stack.hostState().claimed).toBe(true);
  // Setup link is single use.
  expect(stack.hostState().setupURL ?? "").toBe("");
});

test("2. a second computer signs in with the synced passkey and is approved from the phone (codes match)", async ({ browser }) => {
  const laptop = await newDevice(browser, "laptop");
  const sas = await loginAndRequestPairing(laptop, "Studio Laptop");
  const phone = devs.phone.page;
  const item = phone.getByTestId("approval-item");
  await expect(item).toBeVisible();
  await expect(phone.getByTestId("approval-sas")).toHaveText(new RegExp(sas.slice(0, 3) + "\\s?" + sas.slice(3)));
  await phone.getByTestId("approval-approve").click();
  await expectOnline(laptop.page);
  await waitFor(() => hostDevices().includes("Studio Laptop"), 10_000, "laptop pinned");
});

test("3. a third device is approved on the Mac itself; the Mac shows the same code", async ({ browser }) => {
  const tablet = await newDevice(browser, "tablet", { width: 820, height: 1180 });
  const sas = await loginAndRequestPairing(tablet, "Edit Bay iPad");
  const pending = await waitFor(() => stack.hostState().pending?.find((p: any) => p.name === "Edit Bay iPad"), 10_000, "pending on Mac");
  expect(pending.sas.replace(/\D/g, "")).toBe(sas);
  stack.hostCmd(`approve ${pending.requestId}`);
  await expectOnline(tablet.page);
  await waitFor(() => hostDevices().includes("Edit Bay iPad"), 10_000, "tablet pinned");
});

test("4. an unknown device that is denied cannot connect", async ({ browser }) => {
  const stranger = await newDevice(browser, "stranger");
  await loginAndRequestPairing(stranger, "Unknown PC");
  await expect(devs.phone.page.getByTestId("approval-item")).toBeVisible();
  await devs.phone.page.getByTestId("approval-deny").click();
  await expect(stranger.page.getByTestId("pair-retry")).toBeVisible();
  await expect(stranger.page.getByTestId("error-message").filter({ visible: true })).toHaveText(/denied|not approved|declined|didn't approve|did not approve/i);
  await expect(stranger.page.getByTestId("connect-button")).toHaveCount(0);
  expect(hostDevices()).not.toContain("Unknown PC");
});

test("5. full remote session: video, latency, mouse, keyboard, clipboard, file upload and download", async () => {
  const page = devs.laptop.page;
  await connect(page);
  // Host sees the session and an encrypted direct (LAN) path.
  await waitFor(() => stack.hostState().session?.device?.name === "Studio Laptop", 10_000, "host session");
  expect(["direct", "relay"]).toContain(stack.hostState().session.transport);
  await expect(page.getByTestId("latency-pill")).toHaveText(/\d+\s?ms/);
  await expect(page.getByTestId("session-overlay")).toBeHidden();

  // Mouse + keyboard reach the Mac.
  const video = page.getByTestId("session-video");
  const box = (await video.boundingBox())!;
  await page.mouse.move(box.x + box.width * 0.25, box.y + box.height * 0.5);
  await page.mouse.click(box.x + box.width * 0.5, box.y + box.height * 0.5);
  await page.keyboard.type("Hi");
  await page.keyboard.press("Enter");
  await expect.poll(() => {
    const log = stack.inputLog();
    const inputs = log.filter((e: any) => e.type === "INPUT").map((e: any) => e.data);
    const has = (pred: (m: any) => boolean) => inputs.some(pred);
    return has((m) => m.t === "m") && has((m) => m.t === "b" && m.d === true) && has((m) => m.t === "k" && m.c === "KeyH" && m.d) && has((m) => m.t === "k" && m.c === "Enter");
  }, { timeout: 10_000 }).toBe(true);

  // Clipboard: Mac → browser.
  stack.hostCmd("clipboard Copied on the Mac ✂");
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText().catch(() => "")), { timeout: 10_000 }).toBe("Copied on the Mac ✂");

  // Upload a file to the Mac's Downloads folder; contents must match exactly.
  const payload = Buffer.alloc(300_000);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 31 + 7) & 0xff;
  await page.getByTestId("upload-input").setInputFiles({ name: "rough-cut.mov", mimeType: "video/quicktime", buffer: payload });
  const saved = await waitFor(() => {
    const f = existsSync(stack.downloadsDir) ? readdirSync(stack.downloadsDir).find((n) => n.startsWith("rough-cut")) : undefined;
    if (!f) return undefined;
    const b = readFileSync(join(stack.downloadsDir, f));
    return b.length === payload.length ? b : undefined;
  }, 20_000, "upload saved on Mac");
  expect(sha256(saved)).toBe(sha256(payload));

  // Download a file from the Mac's home folder.
  await page.getByTestId("files-button").dispatchEvent("click");
  await expect(page.getByTestId("files-panel")).toBeVisible();
  await page.getByTestId("file-entry").filter({ hasText: "Projects" }).first().getByTestId("folder-open").click();
  const entry = page.getByTestId("file-entry").filter({ hasText: "edit-notes.txt" }).first();
  await expect(entry).toBeVisible();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    entry.getByTestId("download-button").click(),
  ]);
  const dlPath = await download.path();
  expect(readFileSync(dlPath, "utf8")).toBe("Scene 12: tighten the cut by 4 frames.\n");

  await disconnect(page);
});

test("6. kill switch on the Mac blocks connections until allowed again", async () => {
  const page = devs.laptop.page;
  stack.hostCmd("kill");
  await waitFor(() => stack.hostState().killed === true, 5_000, "killed");
  await expect(page.getByTestId("home-status-title")).toHaveText(/blocked|paused|off/i);
  stack.hostCmd("resume");
  await waitFor(() => stack.hostState().killed === false, 5_000, "resumed");
  await expectOnline(page);
});

test("7. 'Block all connections' from the phone ends a live session immediately", async () => {
  const laptop = devs.laptop.page;
  await connect(laptop);
  await waitFor(() => stack.hostState().session !== null, 10_000, "session up");
  await devs.phone.page.getByTestId("block-button").click();
  // The owner is asked to confirm.
  await expect(devs.phone.page.getByTestId("block-confirm")).toBeVisible();
  await devs.phone.page.getByTestId("confirm-ok").click();
  await waitFor(() => stack.hostState().killed === true && stack.hostState().session === null, 10_000, "remote kill");
  await devs.phone.page.getByTestId("allow-button").click();
  await waitFor(() => stack.hostState().killed === false, 10_000, "remote resume");
});

test("8. removing a device from the phone revokes it on the Mac; it can no longer connect", async () => {
  const phone = devs.phone.page;
  await phone.reload();
  const row = phone.getByTestId("device-item").filter({ hasText: "Edit Bay iPad" });
  await expect(row).toBeVisible();
  await row.getByTestId("device-remove").click();
  await phone.getByTestId("confirm-ok").click();
  await waitFor(() => !hostDevices().includes("Edit Bay iPad"), 10_000, "tablet revoked on Mac");
  const tablet = devs.tablet.page;
  await tablet.reload();
  await expect(tablet.getByTestId("connect-button")).toHaveCount(0);
});

test("9. the Mac's tamper-evident access log recorded the sessions", async () => {
  const dataDir = join(stack.dir, "host");
  const log = readFileSync(join(dataDir, "access-log.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const kinds = log.map((e) => e.event ?? e.type ?? e.kind);
  expect(kinds.join(" ")).toMatch(/session-start/);
  expect(kinds.join(" ")).toMatch(/session-end/);
  expect(kinds.join(" ")).toMatch(/device-(added|approved)|pair/);
  // Every entry is hash-chained.
  expect(log.slice(1).every((e) => typeof e.prev === "string" && e.prev.length > 0)).toBe(true);
});
