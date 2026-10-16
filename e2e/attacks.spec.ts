// Attack tests: the signaling server is the adversary. Playwright's
// routeWebSocket sits between the browser and the real server and rewrites
// signaling messages the way a compromised server could. The owner's
// requirement: "even my own server can't intercept or impersonate".
import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import { startStack, addPasskeyAuthenticator, waitFor, type Stack } from "./harness";

test.describe.configure({ mode: "serial" });

let stack: Stack;
let ctx: BrowserContext;
let page: Page;

/** Flips one hex digit of every DTLS fingerprint in an SDP. */
function tamperFingerprint(sdp: string): string {
  return sdp.replace(/(a=fingerprint:sha-256 )([0-9A-F]{2})/gi, (_m, p, b) =>
    p + (b.toUpperCase() === "AA" ? "BB" : "AA"));
}

type Rewrite = (direction: "up" | "down", msg: any) => any;
const passThrough: Rewrite = (_d, msg) => msg;
// One interceptor for the whole file ("the server"); each test picks the attack.
let rewrite: Rewrite = passThrough;

async function interceptSignaling(p: Page, r: Rewrite) {
  rewrite = r;
  void p;
}

async function installMaliciousServer(p: Page) {
  await p.routeWebSocket(/\/ws\/client/, (ws) => {
    const server = ws.connectToServer();
    ws.onMessage((m) => server.send(JSON.stringify(rewrite("up", JSON.parse(String(m))))));
    server.onMessage((m) => ws.send(JSON.stringify(rewrite("down", JSON.parse(String(m))))));
  });
}

test.beforeAll(async ({ browser }) => {
  stack = await startStack(18484);
  ctx = await browser.newContext({ reducedMotion: "reduce" });
  page = await ctx.newPage();
  await installMaliciousServer(page);
  await addPasskeyAuthenticator(page);
  await page.goto(stack.hostState().setupURL);
  await page.getByTestId("setup-create-passkey").click();
  await expect(page.getByTestId("home-status-title")).toHaveText(/online/i);
});

test.afterAll(async () => {
  await ctx?.close();
  await stack?.stop();
});

test("A. server swaps the Mac's DTLS fingerprint in the answer → browser refuses before connecting", async () => {
  let tampered = 0;
  await interceptSignaling(page, (dir, msg) => {
    if (dir === "down" && msg.type === "answer" && typeof msg.sdp === "string") {
      tampered++;
      return { ...msg, sdp: tamperFingerprint(msg.sdp) };
    }
    return msg;
  });
  await page.reload();
  await page.getByTestId("connect-button").click();
  const ended = page.getByTestId("session-ended");
  await expect(ended).toBeVisible({ timeout: 20_000 });
  await expect(ended).toHaveAttribute("data-kind", "security");
  expect(tampered).toBeGreaterThan(0);
  // No media ever flowed: the browser never accepted the forged answer.
  const playing = await page.evaluate(() => {
    const v = document.querySelector("video");
    return !!v && v.currentTime > 0;
  });
  expect(playing).toBe(false);
  rewrite = passThrough;
});

test("B. server swaps the browser's DTLS fingerprint in the offer → the Mac rejects it", async () => {
  await page.reload();
  await expect(page.getByTestId("home-status-title")).toHaveText(/online/i);
  let tampered = 0;
  await interceptSignaling(page, (dir, msg) => {
    if (dir === "up" && msg.type === "offer" && typeof msg.sdp === "string") {
      tampered++;
      return { ...msg, sdp: tamperFingerprint(msg.sdp) };
    }
    return msg;
  });
  await page.reload();
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("session-ended")).toBeVisible({ timeout: 20_000 });
  expect(tampered).toBeGreaterThan(0);
  // The Mac never started a session for the forged offer.
  expect(stack.hostState().session ?? null).toBeNull();
  rewrite = passThrough;
});

test("C. server substitutes its own key in the Mac's answer signature → refused", async () => {
  await page.reload();
  let tampered = 0;
  await interceptSignaling(page, (dir, msg) => {
    if (dir === "down" && msg.type === "answer" && typeof msg.sig === "string") {
      tampered++;
      // A signature the attacker made with its own key: 64 bytes that do not verify.
      return { ...msg, sig: "A".repeat(86) };
    }
    return msg;
  });
  await page.reload();
  await page.getByTestId("connect-button").click();
  const ended = page.getByTestId("session-ended");
  await expect(ended).toBeVisible({ timeout: 20_000 });
  await expect(ended).toHaveAttribute("data-kind", "security");
  expect(tampered).toBeGreaterThan(0);
  rewrite = passThrough;
});

test("D. after the attacks, an untampered connection still works", async () => {
  await page.reload();
  await page.getByTestId("connect-button").click();
  await expect
    .poll(async () => page.evaluate(() => {
      const v = document.querySelector("video");
      return v ? v.videoWidth > 0 && v.currentTime > 0.5 : false;
    }), { timeout: 20_000 })
    .toBe(true);
  await waitFor(() => stack.hostState().session, 10_000, "host session");
});
