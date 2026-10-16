// Compiles test/*.test.ts with esbuild and runs them with `node --test`.
import { build } from "esbuild";
import { readdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const testDir = join(root, "test");
const out = join(root, ".test-out");

rmSync(out, { recursive: true, force: true });
const entries = readdirSync(testDir)
  .filter((f) => f.endsWith(".test.ts"))
  .map((f) => join(testDir, f));

await build({
  entryPoints: entries,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outdir: out,
  outExtension: { ".js": ".mjs" },
  sourcemap: "inline",
  external: ["esbuild"],
  logLevel: "warning",
});

const files = readdirSync(out)
  .filter((f) => f.endsWith(".test.mjs"))
  .sort()
  .map((f) => join(out, f));
const r = spawnSync(process.execPath, ["--test", "--test-reporter=spec", ...files], { stdio: "inherit", cwd: root });
process.exit(r.status ?? 1);
