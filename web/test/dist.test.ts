// Builds the production bundle and checks it is CSP-clean: no inline
// scripts/styles/handlers, only hashed same-origin assets, no source maps,
// no HTML-string sinks, no third-party URLs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const webRoot = resolve(process.cwd());
const out = join(webRoot, ".test-out", "dist");

function scanDist(dir: string): void {
  const files = readdirSync(dir).sort();
  const js = files.filter((f) => /^app\.[A-Z0-9]+\.js$/i.test(f));
  const css = files.filter((f) => /^app\.[A-Z0-9]+\.css$/i.test(f));
  assert.equal(js.length, 1, `one hashed JS bundle in ${dir}: ${files.join(", ")}`);
  assert.equal(css.length, 1, "one hashed CSS bundle");
  for (const f of ["index.html", "favicon.svg", "manifest.webmanifest"]) assert.ok(files.includes(f), `${f} present`);
  assert.deepEqual(
    files.filter((f) => f.endsWith(".map")),
    [],
    "no source maps",
  );
  assert.deepEqual(
    files.filter((f) => !["index.html", "favicon.svg", "manifest.webmanifest", js[0], css[0]].includes(f)),
    [],
    "no unexpected files",
  );

  const html = readFileSync(join(dir, "index.html"), "utf8");
  // Every <script> has a src and no body; there is no <style> element.
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.equal(scripts.length, 1, "exactly one script tag");
  for (const [, attrs, body] of scripts) {
    assert.match(attrs!, /\ssrc="\/app\.[A-Z0-9]+\.js"/i, "script references the hashed bundle");
    assert.equal(body!.trim(), "", "no inline script");
  }
  assert.doesNotMatch(html, /<style\b/i, "no <style>");
  assert.doesNotMatch(html, /\sstyle\s*=/i, "no style attributes");
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "no inline event handlers");
  assert.doesNotMatch(html, /javascript:/i, "no javascript: URLs");
  assert.doesNotMatch(html, /https?:\/\//i, "no absolute (third-party) URLs");
  const links = [...html.matchAll(/<link\b[^>]*href="([^"]+)"/gi)].map((m) => m[1]);
  assert.deepEqual(links.sort(), [`/${css[0]}`, "/favicon.svg", "/manifest.webmanifest"].sort());
  assert.match(html, /<meta name="color-scheme" content="light dark">/);
  assert.match(html, /<meta name="theme-color"/);

  const bundle = readFileSync(join(dir, js[0]!), "utf8");
  for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "createContextualFragment", "DOMParser"]) {
    assert.ok(!bundle.includes(sink), `bundle must not use ${sink}`);
  }
  assert.ok(!/setTimeout\(\s*["'`]/.test(bundle), "no string setTimeout");
  assert.ok(!bundle.includes("sourceMappingURL"), "no source map reference");
  const urls = [...bundle.matchAll(/(?:https?|wss?):\/\/[^\s"'`)]+/g)].map((m) => m[0]);
  assert.deepEqual(
    // (template literals like `https://${host}` are not URLs)
    [...new Set(urls)].filter((u) => u !== "http://www.w3.org/2000/svg" && !u.startsWith("https://${")),
    [],
    "no third-party URLs in the bundle",
  );
  const cssText = readFileSync(join(dir, css[0]!), "utf8");
  assert.ok(!/@import|url\(\s*["']?https?:/i.test(cssText), "CSS loads nothing external");
  assert.ok(!cssText.includes("sourceMappingURL"));
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.webmanifest"), "utf8")) as { icons: Array<{ src: string }> };
  assert.equal(manifest.icons[0]!.src, "/favicon.svg");
}

test("production build is CSP-clean (fresh build)", () => {
  const r = spawnSync(process.execPath, [join(webRoot, "build.mjs"), "--outdir", out], { cwd: webRoot, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  scanDist(out);
});

test("web/dist (if built) is CSP-clean", (t) => {
  const dist = join(webRoot, "dist");
  if (!existsSync(join(dist, "index.html"))) {
    t.skip("dist/ not built yet (run npm run build)");
    return;
  }
  scanDist(dist);
});
