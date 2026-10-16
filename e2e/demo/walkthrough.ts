// Records a slow, captioned walkthrough (phone + laptop side by side) of the
// real system: real server, real host agent core (hostsim plays a test pattern
// in place of the Mac's screen), real Chromium with virtual passkeys.
//
//   cd e2e && npx tsx demo/walkthrough.ts   (or: node --experimental-strip-types)
// Output: e2e/demo/out/*.webm + captions.json, then demo/compose.sh makes an MP4.
import { chromium, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync, readdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { startStack, addPasskeyAuthenticator, copyPasskeys, waitFor } from "../harness.ts";

const OUT = join(import.meta.dirname, "out");
mkdirSync(OUT, { recursive: true });
const stack = await startStack(18282);
const browser = await chromium.launch({
  args: ["--disable-features=WebRtcHideLocalIpsWithMdns", "--autoplay-policy=no-user-gesture-required"],
});
const mk = async (name: string, viewport: { width: number; height: number }) => {
  const ctx = await browser.newContext({ viewport, reducedMotion: "no-preference", recordVideo: { dir: join(OUT, name), size: viewport } });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: stack.origin });
  const page = await ctx.newPage();
  await page.goto("about:blank");
  return { ctx, page, auth: await addPasskeyAuthenticator(page) };
};
const phone = await mk("phone", { width: 390, height: 844 });
const laptop = await mk("laptop", { width: 1280, height: 800 });
const t0 = Date.now();
const captions: { start: number; end?: number; text: string }[] = [];
const say = (text: string) => {
  const now = (Date.now() - t0) / 1000;
  if (captions.length) captions[captions.length - 1].end = now;
  captions.push({ start: now, text });
};
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const slowType = async (page: Page, testid: string, text: string) => {
  const el = page.getByTestId(testid);
  await el.click();
  await el.fill("");
  await el.pressSequentially(text, { delay: 70 });
};

say("Your Mac shows a one-time setup code. You scan it with your phone.");
await pause(1500);
await phone.page.goto(stack.hostState().setupURL);
await pause(2500);
say("Name your phone, then create a passkey. No passwords, ever.");
await slowType(phone.page, "setup-device-name", "My iPhone");
await pause(1000);
await phone.page.getByTestId("setup-create-passkey").click();
await phone.page.getByTestId("home-status").waitFor();
say("Done. Your phone is trusted, and your Mac shows as Online.");
await pause(3500);

say("On a laptop, open your web address and sign in with the same passkey.");
await copyPasskeys(phone.auth, laptop.auth);
await laptop.page.goto(stack.origin + "/");
await pause(2500);
await laptop.page.getByTestId("login-button").click();
await laptop.page.getByTestId("pair-name-input").waitFor();
say("A new device must be approved. Name it and ask for approval.");
await slowType(laptop.page, "pair-name-input", "Studio Laptop");
await pause(800);
await laptop.page.getByTestId("pair-start-button").click();
await laptop.page.getByTestId("pair-sas").waitFor();
say("The laptop shows a 6-digit code…");
await pause(2500);
await phone.page.getByTestId("approval-item").waitFor();
say("…and your phone shows the same code. They match, so you tap Approve.");
await pause(3500);
await phone.page.getByTestId("approval-approve").click();
await laptop.page.getByTestId("connect-button").waitFor();
say("The laptop is now trusted. Click Connect.");
await pause(2500);
await laptop.page.getByTestId("connect-button").click();
await laptop.page.getByTestId("session-video").waitFor();
await waitFor(() => stack.hostState().session, 15000, "session");
say("You're in. (This test pattern stands in for your Mac's screen.) Encrypted end to end.");
await pause(2000);
const box = (await laptop.page.getByTestId("session-video").boundingBox())!;
for (let i = 0; i <= 30; i++) {
  await laptop.page.mouse.move(box.x + box.width * (0.2 + 0.6 * (i / 30)), box.y + box.height * (0.3 + 0.3 * Math.sin(i / 5)));
  await pause(60);
}
say("The corner shows speed: delay in milliseconds, frames per second, and Direct or Relay.");
await pause(4000);
say("Meanwhile your phone shows that someone is connected.");
await pause(3500);
say("Files: send a file to the Mac. It lands in Downloads › Heartfulness Remote.");
await laptop.page.getByTestId("files-button").dispatchEvent("click");
await laptop.page.getByTestId("files-panel").waitFor();
await pause(1500);
await laptop.page.getByTestId("upload-input").setInputFiles({ name: "rough-cut-v3.mov", mimeType: "video/quicktime", buffer: Buffer.alloc(2_000_000, 7) });
await pause(4000);
say("Something feels wrong? Your phone's kill switch ends every session at once.");
await pause(1500);
await phone.page.getByTestId("block-button").click();
await phone.page.getByTestId("confirm-ok").waitFor();
await pause(1500);
await phone.page.getByTestId("confirm-ok").click();
await waitFor(() => stack.hostState().killed && !stack.hostState().session, 15000, "killed");
say("Blocked: the laptop is disconnected and nobody can connect until you allow it again.");
await pause(4500);
await phone.page.getByTestId("allow-button").click();
say("Allow connections, and everything is ready again.");
await pause(3500);
captions[captions.length - 1].end = (Date.now() - t0) / 1000;

const offsets = { phone: 0, laptop: 0 };
await phone.ctx.close();
await laptop.ctx.close();
await browser.close();
await stack.stop();
for (const n of ["phone", "laptop"]) {
  const f = readdirSync(join(OUT, n)).find((x) => x.endsWith(".webm"))!;
  renameSync(join(OUT, n, f), join(OUT, `${n}.webm`));
}
writeFileSync(join(OUT, "captions.json"), JSON.stringify({ captions, offsets }, null, 2));
console.log(`recorded ${captions.length} captions, ${((Date.now() - t0) / 1000).toFixed(0)} s`);
