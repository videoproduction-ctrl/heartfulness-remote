// Entry point. A one-time setup / join secret is read and removed from the
// address bar before anything else runs.

import "./styles.css";
import { App } from "./app";
import { takeFragment } from "./fragment";
import { detectPlatform } from "./platform";

const fragment = takeFragment();

function boot(): void {
  let root = document.getElementById("app");
  if (!root) {
    root = document.createElement("div");
    root.id = "app";
    document.body.appendChild(root);
  }
  const app = new App(detectPlatform(), root, fragment);
  void app.start();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, { once: true });
else boot();
