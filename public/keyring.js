/**
 * keyring.js — on-device keys + local message history, for forward secrecy.
 *
 * THE IDEA
 *   Messages are no longer encrypted to your permanent identity key. Senders
 *   get a ONE-TIME public key of yours from the server, and encrypt to that.
 *   Here on your device we keep the matching private key only until the
 *   message has been read once, then DELETE it. Read messages live in a local,
 *   encrypted "vault" instead of being re-decrypted from the server each time.
 *
 *   Result: if your password or the server's database leaks in future, old
 *   messages can't be decrypted - the keys that could do it no longer exist.
 *
 * WHAT'S STORED (IndexedDB, one database per account)
 *   keys:   { id, kind: "otk"|"epoch", privateKey (non-extractable CryptoKey),
 *             publicKey (base64), createdAt, retiredAt }
 *           Non-extractable = the app can USE the key but no script can read
 *           its bytes out.
 *   vault:  { id: messageId, iv, ct }  AES-GCM; the vault key is derived from
 *           your identity private key, so it can only be opened after you've
 *           typed your password. The server never sees any of this.
 *
 * The storage layer is pluggable (idbStore for browsers, memoryStore for
 * tests) so the cryptography can be tested without a browser.
 */
import { arrayBufferToBase64, base64ToArrayBuffer, exportPublicKey } from "./crypto.js";

const ECDH = { name: "ECDH", namedCurve: "P-256" };
const EPOCH_MAX_AGE_MS = 24 * 60 * 60 * 1000;      // rotate the fallback key daily
const RETIRED_KEEP_MS = 48 * 60 * 60 * 1000;       // keep an old fallback key 2 days for in-flight messages
export const ONE_TIME_LOW_WATER = 20;
export const ONE_TIME_BATCH = 40;

const randomId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

// ---------- storage back-ends ----------
export function memoryStore() {
  const stores = { keys: new Map(), vault: new Map() };
  return {
    async get(s, k) { return stores[s].get(k); },
    async put(s, k, v) { stores[s].set(k, v); },
    async delete(s, k) { stores[s].delete(k); },
    async all(s) { return [...stores[s].values()]; },
    async clear(s) { stores[s].clear(); },
  };
}

export function idbStore(dbName) {
  let dbPromise = null;
  const open = () => (dbPromise ||= new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore("keys", { keyPath: "id" });
      req.result.createObjectStore("vault", { keyPath: "id" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }));
  const run = async (storeName, mode, fn) => {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, mode);
      const result = fn(tx.objectStore(storeName));
      tx.oncomplete = () => resolve(result?.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
    });
  };
  return {
    get: (s, k) => run(s, "readonly", (st) => st.get(k)),
    put: (s, _k, v) => run(s, "readwrite", (st) => st.put(v)),
    delete: (s, k) => run(s, "readwrite", (st) => st.delete(k)),
    all: (s) => run(s, "readonly", (st) => st.getAll()),
    clear: (s) => run(s, "readwrite", (st) => st.clear()),
  };
}

/** Erase a user's whole key ring + vault (used by "Erase messages on this device"). */
export async function eraseLocalData(username) {
  await new Promise((resolve) => {
    const req = indexedDB.deleteDatabase("e2ee-keys:" + username);
    req.onsuccess = req.onerror = req.onblocked = () => resolve();
  });
}

// ---------- the ring ----------
export async function deriveVaultKey(identityJwk) {
  // Only someone holding the identity private key (i.e. who knows the password) can get this.
  const material = new TextEncoder().encode("e2ee-vault-v1|" + identityJwk.d);
  const raw = await crypto.subtle.digest("SHA-256", material);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function newKeyPair() {
  const pair = await crypto.subtle.generateKey(ECDH, false, ["deriveKey"]); // private key non-extractable
  return { privateKey: pair.privateKey, publicKey: await exportPublicKey(pair.publicKey) };
}

export async function createKeyring(store, identityJwk, now = () => Date.now()) {
  const vaultKey = await deriveVaultKey(identityJwk);

  async function putKey(kind) {
    const { privateKey, publicKey } = await newKeyPair();
    const rec = { id: randomId(), kind, privateKey, publicKey, createdAt: now(), retiredAt: null };
    await store.put("keys", rec.id, rec);
    return rec;
  }

  return {
    /** Make `n` one-time keys. Returns the PUBLIC halves to upload. */
    async generateOneTimeKeys(n) {
      const out = [];
      for (let i = 0; i < n; i++) {
        const k = await putKey("otk");
        out.push({ id: k.id, publicKey: k.publicKey });
      }
      return out;
    },

    /** New fallback key; the previous one is retired (kept 2 more days, then pruned). */
    async rotateEpoch() {
      for (const k of await store.all("keys")) {
        if (k.kind === "epoch" && !k.retiredAt) await store.put("keys", k.id, { ...k, retiredAt: now() });
      }
      const k = await putKey("epoch");
      return { id: k.id, publicKey: k.publicKey };
    },

    /** The current (un-retired) fallback key, or null. Used for my own copy of what I send. */
    async currentEpoch() {
      const live = (await store.all("keys")).filter((k) => k.kind === "epoch" && !k.retiredAt);
      live.sort((a, b) => b.createdAt - a.createdAt);
      return live[0] ? { id: live[0].id, publicKey: live[0].publicKey, createdAt: live[0].createdAt } : null;
    },

    async has(keyId) { return !!(await store.get("keys", keyId)); },
    async getPrivate(keyId) { return (await store.get("keys", keyId))?.privateKey || null; },

    /** After a message was read and saved to the vault: one-time keys are destroyed. */
    async consume(keyId) {
      const k = await store.get("keys", keyId);
      if (k && k.kind === "otk") await store.delete("keys", keyId);
    },

    /** Delete fallback keys retired more than 2 days ago. Returns how many were removed. */
    async pruneRetired() {
      let removed = 0;
      for (const k of await store.all("keys")) {
        if (k.kind === "epoch" && k.retiredAt && now() - k.retiredAt > RETIRED_KEEP_MS) {
          await store.delete("keys", k.id);
          removed++;
        }
      }
      return removed;
    },

    /** What does the ring need uploaded? Compares against GET /api/keys/status. */
    async plan(status) {
      const epoch = await this.currentEpoch();
      const ringLost = status.epochId && !(await this.has(status.epochId)); // server knows keys this device doesn't
      return {
        replace: !!ringLost,
        rotateEpoch: !epoch || !status.epochId || ringLost || now() - epoch.createdAt > EPOCH_MAX_AGE_MS,
        oneTimeToMake: ringLost ? ONE_TIME_BATCH : status.oneTimeCount < ONE_TIME_LOW_WATER ? ONE_TIME_BATCH : 0,
      };
    },

    // ----- vault: decrypted messages, encrypted at rest -----
    async vaultPut(messageId, plaintext) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, new TextEncoder().encode(plaintext));
      await store.put("vault", messageId, { id: String(messageId), iv: arrayBufferToBase64(iv), ct: arrayBufferToBase64(ct) });
    },
    async vaultGet(messageId) {
      const rec = await store.get("vault", String(messageId));
      if (!rec) return null;
      try {
        const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToArrayBuffer(rec.iv) }, vaultKey, base64ToArrayBuffer(rec.ct));
        return new TextDecoder().decode(buf);
      } catch {
        return null; // wrong vault key (different password/identity) -> treat as absent
      }
    },
    async vaultDelete(messageId) { await store.delete("vault", String(messageId)); },
    async vaultClear() { await store.clear("vault"); },
  };
}
