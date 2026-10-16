// File transfer state machine over the control + file data channels (§8.1).

import { b64, randomBytes, unb64Len } from "./b64";
import { Assembler, ID_LEN, isSafeEntryName, MAX_TRANSFER_BYTES, parseFrame, safeDownloadName, sendFrames, sha256B64, TransferCancelled } from "./files";
import type { RemoteSession } from "./rtc";

export type TransferState = "hashing" | "waiting" | "sending" | "receiving" | "verifying" | "done" | "error" | "cancelled";

export interface Transfer {
  id: string;
  name: string;
  size: number;
  dir: "up" | "down";
  done: number;
  state: TransferState;
  error?: string;
}

export interface LsEntry {
  name: string;
  dir: boolean;
  size: number;
  mtime: number | string | null;
}

export interface LsResult {
  path: string;
  entries: LsEntry[];
  error?: string;
}

interface Waiter<T> {
  resolve(v: T): void;
  reject(e: Error): void;
}

const ACCEPT_TIMEOUT_MS = 60_000;
const LS_TIMEOUT_MS = 20_000;

/** Plain-language text for a file-reject / file-error reason (agent/internal/core/datachannels.go). */
export function rejectReason(r: unknown): string {
  switch (r) {
    case "too-large":
    case "file too large":
      return "The file is too large for your Mac to accept.";
    case "disk-full":
    case "no-space":
    case "not enough disk space":
      return "Your Mac is out of disk space.";
    case "not-found":
      return "The file no longer exists on your Mac.";
    case "not-a-file":
      return "That item can't be downloaded (it isn't a regular file).";
    case "outside-home":
    case "invalid-path":
      return "Only files inside your Mac's home folder can be downloaded.";
    case "permission-denied":
    case "denied":
    case "forbidden":
      return "Your Mac doesn't allow access to that file.";
    case "busy":
      return "Your Mac is busy with other transfers. Try again in a moment.";
    case "checksum":
    case "bad-hash":
    case "checksum mismatch":
    case "bad sha256 encoding":
    case "incomplete":
    case "more data than announced":
      return "The file was damaged in transfer (checksum mismatch). Please try again.";
    case "file-changed":
      return "The file changed on your Mac while it was being sent. Please try again.";
    case "timeout":
      return "The transfer stalled and was stopped. Please try again.";
    case "read-failed":
    case "write-failed":
      return "Your Mac couldn't read or write the file.";
    default:
      return typeof r === "string" && /^[\w .,'-]{1,80}$/.test(r) ? `Your Mac reported: ${r}` : "The transfer failed.";
  }
}

export class FilesController {
  readonly transfers = new Map<string, Transfer>();
  private downloads = new Map<string, Assembler>();
  private acceptWaiters = new Map<string, Waiter<void>>();
  private resultWaiters = new Map<string, Waiter<string>>();
  private lsWaiters = new Map<string, Waiter<LsResult>>();
  private getRequests = new Map<string, string>();
  private queue: File[] = [];
  private busy = false;
  private cancelled = new Set<string>();
  private lastChange = 0;
  private changeTimer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;

  constructor(
    private readonly session: RemoteSession,
    private readonly onChange: () => void,
    private readonly notify: (msg: string, level: "info" | "error" | "success") => void,
  ) {}

  get activeCount(): number {
    let n = 0;
    for (const t of this.transfers.values()) if (!["done", "error", "cancelled"].includes(t.state)) n++;
    return n + this.queue.length;
  }

  private changed(throttle = false): void {
    if (this.disposed) return;
    const now = performance.now();
    if (throttle && now - this.lastChange < 120) {
      if (!this.changeTimer) this.changeTimer = setTimeout(() => this.changed(), 130);
      return;
    }
    if (this.changeTimer) clearTimeout(this.changeTimer);
    this.changeTimer = null;
    this.lastChange = now;
    this.onChange();
  }

  // ------------------------------------------------------------ control messages

  handleControl(m: Record<string, unknown>): boolean {
    const id = typeof m["id"] === "string" ? m["id"] : "";
    switch (m["t"]) {
      case "ls-result": {
        const w = typeof m["reqId"] === "string" ? this.lsWaiters.get(m["reqId"]) : undefined;
        if (w) {
          this.lsWaiters.delete(m["reqId"] as string);
          w.resolve(this.parseLs(m));
        }
        return true;
      }
      case "file-start":
        this.onDownloadStart(m);
        return true;
      case "file-accept":
        this.acceptWaiters.get(id)?.resolve();
        return true;
      case "file-reject":
        this.acceptWaiters.get(id)?.reject(new Error(rejectReason(m["reason"])));
        return true;
      case "file-end":
        void this.onDownloadEnd(id, m["sha256"]);
        return true;
      case "file-saved":
        this.resultWaiters.get(id)?.resolve(typeof m["name"] === "string" ? m["name"] : "");
        return true;
      case "file-error": {
        const err = new Error(rejectReason(m["reason"]));
        // A download that failed before it started carries only the reqId.
        const reqId = m["reqId"];
        if (id === "" && typeof reqId === "string" && this.getRequests.has(reqId)) {
          const path = this.getRequests.get(reqId) ?? "";
          this.getRequests.delete(reqId);
          const name = path.split("/").pop() || "file";
          this.notify(`Couldn't download “${name}”: ${err.message}`, "error");
          return true;
        }
        if (id === "") return true;
        this.cancelled.add(id);
        this.acceptWaiters.get(id)?.reject(err);
        this.resultWaiters.get(id)?.reject(err);
        if (this.downloads.has(id)) this.failDownload(id, err.message, false);
        return true;
      }
      case "file-cancel": {
        this.cancelled.add(id);
        const err = new TransferCancelled();
        this.acceptWaiters.get(id)?.reject(err);
        this.resultWaiters.get(id)?.reject(err);
        if (this.downloads.has(id)) {
          this.downloads.delete(id);
          this.setState(id, "cancelled");
        }
        return true;
      }
      default:
        return false;
    }
  }

  private setState(id: string, state: TransferState, error?: string): void {
    const t = this.transfers.get(id);
    if (!t) return;
    t.state = state;
    if (error) t.error = error;
    this.changed();
  }

  // ------------------------------------------------------------ browsing

  private parseLs(m: Record<string, unknown>): LsResult {
    const path = typeof m["path"] === "string" ? m["path"] : "";
    const entries: LsEntry[] = [];
    if (Array.isArray(m["entries"])) {
      for (const e of m["entries"].slice(0, 5000)) {
        if (!e || typeof e !== "object") continue;
        const o = e as Record<string, unknown>;
        if (!isSafeEntryName(o["name"])) continue;
        entries.push({
          name: o["name"],
          dir: o["dir"] === true,
          size: typeof o["size"] === "number" ? o["size"] : 0,
          mtime: typeof o["mtime"] === "number" || typeof o["mtime"] === "string" ? o["mtime"] : null,
        });
      }
    }
    entries.sort((a, b) => (a.dir !== b.dir ? (a.dir ? -1 : 1) : a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" })));
    const r: LsResult = { path, entries };
    if (typeof m["error"] === "string" && m["error"] !== "") r.error = m["error"];
    return r;
  }

  ls(path: string): Promise<LsResult> {
    const reqId = b64(randomBytes(9));
    return new Promise<LsResult>((resolve, reject) => {
      const t = setTimeout(() => {
        this.lsWaiters.delete(reqId);
        reject(new Error("Your Mac didn't answer."));
      }, LS_TIMEOUT_MS);
      this.lsWaiters.set(reqId, {
        resolve: (v) => {
          clearTimeout(t);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(t);
          reject(e);
        },
      });
      if (!this.session.sendControl({ t: "ls", reqId, path })) {
        clearTimeout(t);
        this.lsWaiters.delete(reqId);
        reject(new Error("Not connected."));
      }
    });
  }

  // ------------------------------------------------------------ downloads (Mac → here)

  download(path: string): void {
    const reqId = b64(randomBytes(9));
    this.getRequests.set(reqId, path);
    if (!this.session.sendControl({ t: "get", reqId, path })) {
      this.getRequests.delete(reqId);
      this.notify("Not connected.", "error");
      return;
    }
    setTimeout(() => this.getRequests.delete(reqId), ACCEPT_TIMEOUT_MS);
  }

  private onDownloadStart(m: Record<string, unknown>): void {
    const id = m["id"];
    const reqId = m["reqId"];
    if (m["dir"] !== "down" || typeof id !== "string") return;
    try {
      unb64Len(id, ID_LEN);
    } catch {
      return;
    }
    // Only accept downloads we asked for.
    if (typeof reqId !== "string" || !this.getRequests.has(reqId)) {
      this.session.sendControl({ t: "file-cancel", id });
      return;
    }
    this.getRequests.delete(reqId);
    const name = typeof m["name"] === "string" && m["name"] !== "" ? m["name"] : "download";
    const size = m["size"];
    const t: Transfer = { id, name, size: typeof size === "number" ? size : 0, dir: "down", done: 0, state: "receiving" };
    this.transfers.set(id, t);
    try {
      if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) throw new Error("Invalid file size.");
      if (size > MAX_TRANSFER_BYTES) throw new Error("This file is too large to download in the browser (limit 2 GB).");
      this.downloads.set(id, new Assembler(id, name, size));
    } catch (e) {
      this.failDownload(id, e instanceof Error ? e.message : "Download failed.", true);
      return;
    }
    this.changed();
  }

  handleData(buf: ArrayBuffer): void {
    const f = parseFrame(buf);
    if (!f) return;
    const a = this.downloads.get(f.id);
    if (!a) return;
    try {
      a.push(f.chunk);
    } catch (e) {
      this.failDownload(f.id, e instanceof Error ? e.message : "Download failed.", true);
      return;
    }
    const t = this.transfers.get(f.id);
    if (t) {
      t.done = a.received;
      this.changed(true);
    }
  }

  private async onDownloadEnd(id: string, sha: unknown): Promise<void> {
    const a = this.downloads.get(id);
    if (!a) return;
    this.downloads.delete(id);
    this.setState(id, "verifying");
    try {
      if (typeof sha !== "string") throw new Error("The Mac didn't send a checksum.");
      const blob = await a.finish(sha);
      saveBlob(blob, a.name);
      this.setState(id, "done");
      this.notify(`Downloaded “${a.name}”.`, "success");
    } catch (e) {
      this.setState(id, "error", e instanceof Error ? e.message : "Download failed.");
    }
  }

  private failDownload(id: string, msg: string, tellHost: boolean): void {
    this.downloads.delete(id);
    if (tellHost) this.session.sendControl({ t: "file-cancel", id });
    this.setState(id, "error", msg);
  }

  // ------------------------------------------------------------ uploads (here → Mac)

  enqueue(files: Iterable<File>): void {
    for (const f of files) this.queue.push(f);
    this.changed();
    void this.pump();
  }

  private async pump(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      while (this.queue.length && !this.disposed) {
        const f = this.queue.shift()!;
        await this.upload(f);
      }
    } finally {
      this.busy = false;
    }
  }

  private wait<T>(map: Map<string, Waiter<T>>, id: string, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const t = setTimeout(() => {
        map.delete(id);
        reject(new Error("Your Mac didn't answer."));
      }, ms);
      map.set(id, {
        resolve: (v) => {
          clearTimeout(t);
          map.delete(id);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(t);
          map.delete(id);
          reject(e);
        },
      });
    });
  }

  private async upload(file: File): Promise<void> {
    const idBytes = randomBytes(ID_LEN);
    const id = b64(idBytes);
    const t: Transfer = { id, name: file.name || "file", size: file.size, dir: "up", done: 0, state: "hashing" };
    this.transfers.set(id, t);
    this.changed();
    let result: Promise<string> | null = null;
    try {
      if (file.size > MAX_TRANSFER_BYTES) throw new Error("This file is too large to send from the browser (limit 2 GB).");
      const data = new Uint8Array(await file.arrayBuffer());
      const sha = await sha256B64(data);
      if (this.cancelled.has(id)) throw new TransferCancelled();
      const ch = this.session.file;
      if (!ch) throw new Error("Not connected.");
      t.state = "waiting";
      this.changed();
      const accepted = this.wait(this.acceptWaiters, id, ACCEPT_TIMEOUT_MS);
      if (!this.session.sendControl({ t: "file-start", id, name: t.name, size: file.size, dir: "up" })) throw new Error("Not connected.");
      await accepted;
      // Register before file-end so a fast reply isn't missed (and errors during sending are caught).
      result = this.wait(this.resultWaiters, id, 120_000 + file.size / 1000);
      result.catch(() => undefined);
      t.state = "sending";
      this.changed();
      await sendFrames(
        ch,
        idBytes,
        data,
        (n) => {
          t.done = n;
          this.changed(true);
        },
        () => this.cancelled.has(id) || this.disposed,
      );
      t.state = "verifying";
      this.changed();
      if (!this.session.sendControl({ t: "file-end", id, sha256: sha })) throw new Error("Not connected.");
      const savedAs = await result;
      t.state = "done";
      this.changed();
      this.notify(`Sent “${savedAs || t.name}” to Downloads › Heartfulness Remote on your Mac.`, "success");
    } catch (e) {
      if (e instanceof TransferCancelled || this.cancelled.has(id)) {
        if (t.state !== "error") {
          t.state = "cancelled";
          this.session.sendControl({ t: "file-cancel", id });
        }
      } else {
        t.state = "error";
        t.error = e instanceof Error ? e.message : "Upload failed.";
      }
      this.changed();
    } finally {
      this.acceptWaiters.delete(id);
      this.resultWaiters.delete(id);
    }
  }

  cancel(id: string): void {
    const t = this.transfers.get(id);
    if (!t || ["done", "error", "cancelled"].includes(t.state)) return;
    this.cancelled.add(id);
    if (t.dir === "down") {
      this.downloads.delete(id);
      this.session.sendControl({ t: "file-cancel", id });
      this.setState(id, "cancelled");
    } else {
      this.acceptWaiters.get(id)?.reject(new TransferCancelled());
      this.resultWaiters.get(id)?.reject(new TransferCancelled());
      if (t.state === "verifying") this.session.sendControl({ t: "file-cancel", id });
    }
  }

  clearFinished(): void {
    for (const [k, t] of this.transfers) if (["done", "error", "cancelled"].includes(t.state)) this.transfers.delete(k);
    this.changed();
  }

  dispose(): void {
    this.disposed = true;
    this.queue = [];
    if (this.changeTimer) clearTimeout(this.changeTimer);
    for (const w of this.lsWaiters.values()) w.reject(new Error("Session ended."));
    this.lsWaiters.clear();
    this.downloads.clear();
  }
}

/** Saves a verified Blob with an <a download> blob: URL. */
export function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = safeDownloadName(name);
  a.rel = "noopener";
  a.hidden = true;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
