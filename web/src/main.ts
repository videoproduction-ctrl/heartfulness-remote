// Entry point. The one-time setup secret is read and removed from the address
// bar before anything else runs.

import "./styles.css";
import { App } from "./app";
import { takeSetupFragment } from "./fragment";
import { detectPlatform } from "./platform";
import { toast } from "./ui";

const setup = takeSetupFragment();

function boot(): void {
  let root = document.getElementById("app");
  if (!root) {
    root = document.createElement("div");
    root.id = "app";
    document.body.appendChild(root);
  }
  const app = new App(detectPlatform(), root, setup === "invalid" ? null : setup);
  if (setup === "invalid") toast("This setup link is damaged. On your Mac, show the QR code again and rescan it.", "error", 9000);
  void app.start();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, { once: true });
else boot();
