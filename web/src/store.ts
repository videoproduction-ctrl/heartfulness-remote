// Minimal IndexedDB key/value store. Holds the browser's non-extractable
// device key (CryptoKey objects are structured-cloneable) and pinned host keys.

const DB_NAME = "heartfulness-remote";
const STORE = "kv";

let dbPromise: Promise<IDBDatabase> | null = null;

function openDB(): Promise<IDBDatabase> {
  if (!dbPromise) {
    dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      if (typeof indexedDB === "undefined") {
        reject(new Error("This browser has no IndexedDB storage."));
        return;
      }
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => {
        const db = req.result;
        db.onversionchange = () => {
          db.close();
          dbPromise = null;
        };
        resolve(db);
      };
      req.onerror = () => reject(req.error ?? new Error("Could not open storage."));
      req.onblocked = () => reject(new Error("Storage is blocked by another tab."));
    });
    dbPromise.catch(() => {
      dbPromise = null;
    });
  }
  return dbPromise;
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await openDB();
  return new Promise<T>((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = fn(t.objectStore(STORE));
    let result: T;
    req.onsuccess = () => {
      result = req.result as T;
    };
    t.oncomplete = () => resolve(result);
    t.onerror = () => reject(t.error ?? req.error ?? new Error("Storage error."));
    t.onabort = () => reject(t.error ?? new Error("Storage transaction aborted."));
  });
}

export function kvGet<T>(key: string): Promise<T | undefined> {
  return tx<T | undefined>("readonly", (s) => s.get(key));
}

export async function kvSet(key: string, value: unknown): Promise<void> {
  await tx("readwrite", (s) => s.put(value, key));
}

export async function kvDel(key: string): Promise<void> {
  await tx("readwrite", (s) => s.delete(key));
}

/** Asks the browser not to evict our storage (losing the device key forces re-pairing). */
export async function requestPersistence(): Promise<void> {
  try {
    if (navigator.storage && typeof navigator.storage.persist === "function") {
      if (!(await navigator.storage.persisted())) await navigator.storage.persist();
    }
  } catch {
    // Best effort only.
  }
}
