// Builds web/dist: index.html, app.[hash].js, app.[hash].css, favicon.svg,
// manifest.webmanifest. Production builds are minified without source maps.
//
//   node build.mjs                 production build into ./dist
//   node build.mjs --outdir <dir>  production build elsewhere (used by tests)
//   node build.mjs --watch         development watch build (source maps)

import * as esbuild from "esbuild";
import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const watch = args.includes("--watch");
const outIdx = args.indexOf("--outdir");
const outdir = outIdx >= 0 && args[outIdx + 1] ? resolve(args[outIdx + 1]) : join(root, "dist");

// Browsers with WebCrypto Ed25519 are newer than this anyway.
const TARGETS = ["es2022", "chrome111", "edge111", "firefox115", "safari16.4"];
const STATIC = ["favicon.svg", "manifest.webmanifest"];

function indexHTML(js, css) {
  // No inline scripts or styles: the server's CSP forbids them.
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f5f5f7" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#000000" media="(prefers-color-scheme: dark)">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<meta name="description" content="Securely control your Mac from anywhere.">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Remote">
<title>Heartfulness Remote</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="stylesheet" href="/${css}">
<script defer src="/${js}"></script>
</head>
<body>
<div id="app"></div>
<noscript><p>Heartfulness Remote needs JavaScript to be turned on.</p></noscript>
</body>
</html>
`;
}

function finish(result) {
  if (result.errors.length) return;
  const outputs = Object.keys(result.metafile.outputs).map((f) => basename(f));
  const js = outputs.find((f) => /^app\.[A-Z0-9]+\.js$/i.test(f));
  const css = outputs.find((f) => /^app\.[A-Z0-9]+\.css$/i.test(f));
  if (!js || !css) throw new Error(`build did not produce app.[hash].js/.css (got ${outputs.join(", ")})`);
  writeFileSync(join(outdir, "index.html"), indexHTML(js, css));
  for (const f of STATIC) copyFileSync(join(root, "static", f), join(outdir, f));
  // Remove stale hashed bundles from earlier (watch) builds.
  const keep = new Set([...outputs, "index.html", ...STATIC]);
  for (const f of readdirSync(outdir)) {
    if (/^app\.[A-Z0-9]+\.(js|css)(\.map)?$/i.test(f) && !keep.has(f)) rmSync(join(outdir, f));
  }
}

const options = {
  entryPoints: [join(root, "src", "main.ts")],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: TARGETS,
  outdir,
  entryNames: "app.[hash]",
  minify: !watch,
  sourcemap: watch ? "linked" : false,
  legalComments: "none",
  charset: "ascii",
  metafile: true,
  logLevel: "info",
  drop: watch ? [] : ["debugger"],
  plugins: [
    {
      name: "hr-html",
      setup(build) {
        build.onEnd((result) => finish(result));
      },
    },
  ],
};

if (!watch && existsSync(outdir)) rmSync(outdir, { recursive: true, force: true });
mkdirSync(outdir, { recursive: true });

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log(`watching… output in ${outdir}`);
} else {
  await esbuild.build(options);
}
