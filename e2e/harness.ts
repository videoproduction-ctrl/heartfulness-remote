// Test harness: starts the real server and the host simulator (a stand-in for
// the Mac app, using the real Go agent core), and gives each browser context a
// CDP virtual WebAuthn authenticator so passkeys are created and used for real.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { BrowserContext, Page, CDPSession } from "@playwright/test";

export const ROOT = resolve(import.meta.dirname, "..");
export const BIN = join(ROOT, "e2e", ".bin");

export interface Stack {
  origin: string;
  dir: string;
  server: ChildProcess;
  host: ChildProcess;
  hostState(): any;
  hostCmd(line: string): void;
  inputLog(): any[];
  downloadsDir: string;
  homeDir: string;
  stop(): Promise<void>;
}

function waitFor<T>(fn: () => T | undefined | false, ms: number, what: string): Promise<T> {
  const start = Date.now();
  return new Promise((res, rej) => {
    const tick = () => {
      let v: T | undefined | false;
      try { v = fn(); } catch { v = undefined; }
      if (v) return res(v as T);
      if (Date.now() - start > ms) return rej(new Error(`timed out waiting for ${what}`));
      setTimeout(tick, 100);
    };
    tick();
  });
}

export { waitFor };

async function httpOK(url: string): Promise<boolean> {
  try {
    const r = await fetch(url);
    return r.ok;
  } catch {
    return false;
  }
}

export async function startStack(port: number, opts: { hostArgs?: string[] } = {}): Promise<Stack> {
  const dir = mkdtempSync(join(tmpdir(), "hr-e2e-"));
  const origin = `http://localhost:${port}`;
  const downloadsDir = join(dir, "downloads");
  const homeDir = join(dir, "home");
  mkdirSync(join(homeDir, "Projects"), { recursive: true });
  writeFileSync(join(homeDir, "Projects", "edit-notes.txt"), "Scene 12: tighten the cut by 4 frames.\n");
  mkdirSync(downloadsDir, { recursive: true });

  const server = spawn(join(BIN, "heartfulness-server"), ["serve"], {
    env: {
      ...process.env,
      HR_ORIGIN: origin,
      HR_LISTEN: `127.0.0.1:${port}`,
      HR_DATA_DIR: join(dir, "server"),
      HR_TURN_SECRET: "e2e-turn-secret",
      HR_WEB_DIR: join(ROOT, "web", "dist"),
      HR_DEV: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout!.on("data", (d) => process.env.E2E_VERBOSE && process.stdout.write(`[server] ${d}`));
  server.stderr!.on("data", (d) => process.env.E2E_VERBOSE && process.stderr.write(`[server] ${d}`));
  let up = false;
  for (let i = 0; i < 150 && !(up = await httpOK(`${origin}/healthz`)); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!up) throw new Error("server did not start");

  const stateFile = join(dir, "host-state.json");
  const inputFile = join(dir, "host-input.jsonl");
  const host = spawn(
    join(BIN, "hostsim"),
    [
      "--server", origin,
      "--data", join(dir, "host"),
      "--key", join(dir, "host", "host.key"),
      "--video", join(ROOT, "agent", "testdata", "test.ivf"),
      ...(existsSync(join(ROOT, "agent", "testdata", "test.ogg"))
        ? ["--audio", join(ROOT, "agent", "testdata", "test.ogg")]
        : []),
      "--fps", "30",
      "--state-file", stateFile,
      "--input-log", inputFile,
      "--downloads", downloadsDir,
      "--home", homeDir,
      ...(opts.hostArgs ?? []),
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  host.stdout!.on("data", (d) => process.env.E2E_VERBOSE && process.stdout.write(`[host] ${d}`));
  host.stderr!.on("data", (d) => process.env.E2E_VERBOSE && process.stderr.write(`[host] ${d}`));

  const hostState = () => (existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, "utf8")) : {});
  const inputLog = () =>
    existsSync(inputFile)
      ? readFileSync(inputFile, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l))
      : [];

  await waitFor(() => hostState().server === "online", 15000, "host online");

  return {
    origin, dir, server, host, hostState, inputLog, downloadsDir, homeDir,
    hostCmd: (line: string) => host.stdin!.write(line + "\n"),
    async stop() {
      host.stdin!.write("quit\n");
      await new Promise((r) => setTimeout(r, 200));
      host.kill("SIGTERM");
      server.kill("SIGTERM");
    },
  };
}

/** Adds a CTAP2 platform authenticator with resident keys + user verification. */
export async function addPasskeyAuthenticator(page: Page): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, id: authenticatorId };
}

/** Simulates a synced passkey (iCloud Keychain / Google Password Manager). */
export async function copyPasskeys(
  from: { cdp: CDPSession; id: string },
  to: { cdp: CDPSession; id: string },
): Promise<number> {
  const { credentials } = await from.cdp.send("WebAuthn.getCredentials", { authenticatorId: from.id });
  for (const c of credentials) {
    await to.cdp.send("WebAuthn.addCredential", { authenticatorId: to.id, credential: c });
  }
  return credentials.length;
}

export async function grantClipboard(ctx: BrowserContext, origin: string) {
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin });
}
