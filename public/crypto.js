/**
 * crypto.js — All encryption for this app lives here.
 *
 * Design:
 *  - Each browser generates a fresh ECDH (P-256) keypair when it opens a room.
 *    The private key NEVER leaves the browser (non-extractable) and is held
 *    only in memory - closing the tab destroys it (perfect forward secrecy
 *    per session).
 *  - Only the PUBLIC key is sent through the signaling server. Public keys
 *    are, by definition, safe to expose - they cannot be used to decrypt
 *    anything.
 *  - Both sides run ECDH locally to derive an identical AES-256-GCM key.
 *    This shared key is never transmitted anywhere, by anyone, ever.
 *  - Every message/file chunk gets its own random 96-bit IV (required for
 *    AES-GCM security - IVs must never repeat under the same key).
 */

const ECDH_PARAMS = { name: "ECDH", namedCurve: "P-256" };

export async function generateKeyPair() {
  return crypto.subtle.generateKey(ECDH_PARAMS, false /* non-extractable private key */, [
    "deriveKey",
  ]);
}

export async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  return arrayBufferToBase64(raw);
}

export async function importPublicKey(base64) {
  const raw = base64ToArrayBuffer(base64);
  return crypto.subtle.importKey("raw", raw, ECDH_PARAMS, false, []);
}

/** Derive the shared AES-GCM key both peers will now hold identically. */
export async function deriveSharedKey(privateKey, peerPublicKey) {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Encrypt an ArrayBuffer (or string) -> { iv: base64, data: base64 } */
export async function encrypt(sharedKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plainBuf =
    typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    plainBuf
  );
  return {
    iv: arrayBufferToBase64(iv),
    data: arrayBufferToBase64(cipherBuf),
  };
}

/** Decrypt { iv, data } (base64 strings) -> ArrayBuffer */
export async function decrypt(sharedKey, ivB64, dataB64) {
  const iv = base64ToArrayBuffer(ivB64);
  const cipherBuf = base64ToArrayBuffer(dataB64);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, sharedKey, cipherBuf);
}

export async function decryptToText(sharedKey, ivB64, dataB64) {
  const buf = await decrypt(sharedKey, ivB64, dataB64);
  return new TextDecoder().decode(buf);
}

/** A short, human-verifiable fingerprint of the shared key (for out-of-band verification). */
export async function keyFingerprint(sharedKey) {
  // We can't export a non-extractable key, so instead we hash the two public
  // keys' concatenation - callers pass that in. Kept here for symmetry.
  return null; // see app.js: fingerprint is computed from the two public keys directly.
}

export function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/* ============================================================================
 * Persistent identity keys + async messaging (ECIES)
 * ----------------------------------------------------------------------------
 * Used by the WhatsApp-style "Messages" feature (login.js / messages.js),
 * as opposed to the ephemeral per-room keys above (used by the Quick Rooms
 * feature in app.js). The difference: Quick Rooms keys only need to exist
 * while both people are online in the same room, so they can be thrown away
 * when the tab closes. Messages need to work when the recipient is offline,
 * so the identity key has to survive across logins/devices — which means it
 * has to be recoverable from something the user carries in their head: their
 * password.
 * ==========================================================================*/

const EXTRACTABLE_ECDH_PARAMS = { name: "ECDH", namedCurve: "P-256" };

/** A user's long-term identity keypair. Unlike generateKeyPair() above,
 *  this one IS extractable — we need to export+encrypt the private key so
 *  it can be recovered later via the user's password. */
export async function generateIdentityKeyPair() {
  return crypto.subtle.generateKey(EXTRACTABLE_ECDH_PARAMS, true, ["deriveKey"]);
}

/** Derive an AES-GCM key from a password + salt via PBKDF2. Same password
 *  + same salt always produces the same key — that's what lets a user
 *  recover their private key on a new device just by logging in. */
export async function deriveKeyFromPassword(password, saltB64) {
  const salt = saltB64 ? base64ToArrayBuffer(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  return { aesKey, saltB64: arrayBufferToBase64(salt) };
}

/** Export an identity private key, encrypt it with the password-derived
 *  AES key, and package it for the server to store (server can't decrypt
 *  it — it never has the password, only ever a bcrypt hash of it). */
export async function wrapPrivateKey(privateKey, passwordAesKey) {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const { iv, data } = await encrypt(passwordAesKey, JSON.stringify(jwk));
  return { ciphertext: data, iv };
}

/** Reverse of wrapPrivateKey: recover the usable CryptoKey from the
 *  encrypted blob, using the password-derived AES key. Extractable=true
 *  here (unlike the final "hot" key used for actual decryption) because
 *  callers need to re-export this to JWK once more, to cache it in
 *  sessionStorage for the rest of the browser session. */
export async function unwrapPrivateKey(wrapped, passwordAesKey) {
  const jwkText = await decryptToText(passwordAesKey, wrapped.iv, wrapped.ciphertext);
  const jwk = JSON.parse(jwkText);
  return crypto.subtle.importKey("jwk", jwk, EXTRACTABLE_ECDH_PARAMS, true, ["deriveKey"]);
}

export async function exportIdentityPublicKey(publicKey) {
  return exportPublicKey(publicKey); // same raw-base64 format as the room-key one
}

export async function importIdentityPublicKey(base64) {
  return crypto.subtle.importKey("raw", base64ToArrayBuffer(base64), EXTRACTABLE_ECDH_PARAMS, true, []);
}

/**
 * ECIES: encrypt a message to someone's public key without needing them
 * online. Generates a fresh, one-time (ephemeral) keypair, derives a shared
 * secret with the recipient's long-term public key, encrypts with it, then
 * discards the ephemeral private key — only its PUBLIC half travels with
 * the message, so the recipient can redo the same ECDH on their end.
 */
export async function encryptToPublicKey(recipientPublicKeyB64, plaintext) {
  const recipientPublicKey = await importIdentityPublicKey(recipientPublicKeyB64);
  const ephemeral = await crypto.subtle.generateKey(EXTRACTABLE_ECDH_PARAMS, false, ["deriveKey"]);
  const sharedKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: recipientPublicKey },
    ephemeral.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const { iv, data } = await encrypt(sharedKey, plaintext);
  const ephemeralPublicKey = await exportPublicKey(ephemeral.publicKey);
  return { ephemeralPublicKey, iv, ciphertext: data };
}

/** Reverse of encryptToPublicKey, run with the recipient's own long-term
 *  private key (recovered via unwrapPrivateKey at login). */
export async function decryptFromPublicKey(myPrivateKey, ephemeralPublicKeyB64, ivB64, ciphertextB64) {
  const ephemeralPublicKey = await importPublicKey(ephemeralPublicKeyB64);
  const sharedKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: ephemeralPublicKey },
    myPrivateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  return decryptToText(sharedKey, ivB64, ciphertextB64);
}
