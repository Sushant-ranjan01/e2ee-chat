/**
 * applock.js — PIN lock (+ optional fingerprint) for the whole app.
 *
 * What it protects against: someone picking up your UNLOCKED phone, or
 * opening the app after you switch away. The app shows an opaque lock screen
 * until the right PIN (or fingerprint) is given. Settings: Settings & privacy.
 *
 * Honest limits: this is a screen lock, not extra disk encryption - the phone's
 * own screen lock / storage encryption still matters. After too many wrong PINs
 * the account is signed out and the local message history on this device is erased.
 *
 * Every page that shows chats calls initAppLock() once, at the top.
 */
import { biometricAvailable, biometricAuth, setSecureScreen, isNative } from "./native.js";

const KEY = "e2ee_applock";
const SECURE_KEY = "e2ee_secure_screen";
const SEEN = "e2ee_last_seen";
const PBKDF2_ITERATIONS = 200000;
const MAX_FAILS = 10; // then: sign out + erase local data
const TIMEOUTS = [15, 60, 300, 900]; // seconds - choices offered in settings

// ---------- storage ----------
function read() {
  try { return JSON.parse(localStorage.getItem(KEY) || "null"); } catch { return null; }
}
function write(cfg) {
  localStorage.setItem(KEY, JSON.stringify(cfg));
}
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function hashPin(pin, saltB64, iterations = PBKDF2_ITERATIONS) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unb64(saltB64), iterations, hash: "SHA-256" }, base, 256);
  return b64(bits);
}

export const PIN_REGEX = /^\d{4,8}$/;
export const lockTimeouts = TIMEOUTS;

export function isLockEnabled() {
  return !!read()?.hash;
}
export function getLockSettings() {
  const c = read() || {};
  return { enabled: !!c.hash, timeoutSec: c.timeoutSec || 60, biometric: !!c.biometric };
}

export async function enableLock(pin) {
  if (!PIN_REGEX.test(pin)) throw new Error("PIN must be 4 to 8 digits.");
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await hashPin(pin, salt);
  write({ v: 1, salt, hash, iterations: PBKDF2_ITERATIONS, timeoutSec: read()?.timeoutSec || 60, biometric: !!read()?.biometric, fails: 0, lockedUntil: 0 });
  touch();
}

/** True if `pin` is right (does NOT count toward the wrong-PIN limit - used from Settings). */
export async function checkPin(pin) {
  const c = read();
  if (!c?.hash) return false;
  return (await hashPin(pin, c.salt, c.iterations)) === c.hash;
}

export async function disableLock(pin) {
  if (!(await checkPin(pin))) throw new Error("Wrong PIN.");
  localStorage.removeItem(KEY);
}
export async function changePin(oldPin, newPin) {
  if (!(await checkPin(oldPin))) throw new Error("Wrong current PIN.");
  const keep = read();
  await enableLock(newPin);
  write({ ...read(), timeoutSec: keep.timeoutSec, biometric: keep.biometric });
}
export function setLockTimeout(sec) {
  const c = read();
  if (c) write({ ...c, timeoutSec: TIMEOUTS.includes(sec) ? sec : 60 });
}
export function setBiometric(on) {
  const c = read();
  if (c) write({ ...c, biometric: !!on });
}
export { biometricAvailable };

export function isSecureScreenOn() {
  return localStorage.getItem(SECURE_KEY) !== "0"; // default ON
}
export async function setSecureScreenPref(on) {
  localStorage.setItem(SECURE_KEY, on ? "1" : "0");
  await setSecureScreen(on);
}

// ---------- "last seen active" bookkeeping ----------
function touch() {
  sessionStorage.setItem(SEEN, String(Date.now()));
}
function shouldLock() {
  const c = read();
  if (!c?.hash || !localStorage.getItem("e2ee_token")) return false;
  const seen = Number(sessionStorage.getItem(SEEN) || 0);
  if (!seen) return true; // fresh app start
  return Date.now() - seen > (c.timeoutSec || 60) * 1000;
}

// ---------- erase everything local (too many wrong PINs) ----------
async function wipeAndSignOut() {
  try {
    const dbs = (await indexedDB.databases?.()) || [];
    for (const d of dbs) if (d.name) indexedDB.deleteDatabase(d.name);
  } catch { /* ignore */ }
  for (const k of ["e2ee_token", "e2ee_username", "e2ee_phone", "e2ee_public_key", "e2ee_push_token", KEY]) localStorage.removeItem(k);
  sessionStorage.clear();
  window.location.href = "/login.html";
}

// ---------- lock screen ----------
let overlay = null;
let locked = false;

function buildOverlay() {
  const el = document.createElement("div");
  el.id = "appLockOverlay";
  el.innerHTML = `
    <div class="lock-card">
      <div class="lock-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
      </div>
      <h1>SecureChat is locked</h1>
      <p class="lock-sub">Enter your PIN to continue</p>
      <input id="lockPin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="8" autocomplete="off" placeholder="PIN" aria-label="PIN" />
      <p id="lockError" class="lock-error" role="alert"></p>
      <button id="lockUnlockBtn" class="primary">Unlock</button>
      <button id="lockBioBtn" class="lock-bio hidden">Use fingerprint</button>
      <button id="lockForgotBtn" class="lock-forgot">Forgot PIN? Sign out</button>
    </div>`;
  document.body.appendChild(el);
  return el;
}

function ui(id) { return overlay.querySelector("#" + id); }

async function tryBiometric() {
  const ok = await biometricAuth({ title: "Unlock SecureChat", subtitle: "Confirm it's you", cancel: "Use PIN" });
  if (ok) unlock(true);
}

function lockNow() {
  if (locked || !isLockEnabled()) return;
  locked = true;
  overlay = overlay || buildOverlay();
  overlay.classList.add("show");
  document.documentElement.classList.add("app-locked");
  ui("lockPin").value = "";
  ui("lockError").textContent = "";

  const cfg = read();
  ui("lockBioBtn").classList.add("hidden");
  if (cfg.biometric) {
    biometricAvailable().then((ok) => {
      if (!ok || !locked) return;
      ui("lockBioBtn").classList.remove("hidden");
      tryBiometric();
    });
  } else {
    setTimeout(() => ui("lockPin").focus(), 50);
  }
}

function unlock() {
  locked = false;
  overlay?.classList.remove("show");
  document.documentElement.classList.remove("app-locked");
  const c = read();
  if (c) write({ ...c, fails: 0, lockedUntil: 0 });
  touch();
}

async function submitPin() {
  const c = read();
  if (!c) return unlock();
  const now = Date.now();
  if (c.lockedUntil && now < c.lockedUntil) {
    ui("lockError").textContent = `Too many tries. Wait ${Math.ceil((c.lockedUntil - now) / 1000)} s.`;
    return;
  }
  const pin = ui("lockPin").value;
  if (await checkPin(pin)) return unlock();

  const fails = (c.fails || 0) + 1;
  if (fails >= MAX_FAILS) return wipeAndSignOut();
  // 3rd wrong: 30 s, 5th: 5 min, 8th: 30 min
  const wait = fails >= 8 ? 1800 : fails >= 5 ? 300 : fails >= 3 ? 30 : 0;
  write({ ...c, fails, lockedUntil: wait ? now + wait * 1000 : 0 });
  ui("lockPin").value = "";
  const left = MAX_FAILS - fails;
  ui("lockError").textContent =
    (wait ? `Wrong PIN. Locked for ${wait >= 60 ? wait / 60 + " min" : wait + " s"}. ` : "Wrong PIN. ") +
    (left <= 3 ? `${left} ${left === 1 ? "try" : "tries"} left before this device is signed out and wiped.` : "");
}

/** Call once per page. Safe to call when no lock is set (does nothing). */
export function initAppLock() {
  // Apply the screenshot-block preference (the app starts with it ON).
  setSecureScreen(isSecureScreenOn());

  if (shouldLock()) lockNow();
  else touch();

  // Keep "last active" fresh while the page is visible; stop when hidden so
  // coming back after the timeout locks again.
  setInterval(() => { if (!document.hidden && !locked) touch(); }, 3000);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { if (!locked) touch(); }
    else if (shouldLock()) lockNow();
  });
  window.addEventListener("pagehide", () => { if (!locked) touch(); });

  document.addEventListener("click", (e) => {
    if (!overlay || !locked) return;
    if (e.target.closest("#lockUnlockBtn")) submitPin();
    else if (e.target.closest("#lockBioBtn")) tryBiometric();
    else if (e.target.closest("#lockForgotBtn")) {
      if (confirm("Sign out? Your PIN lock is removed and the message history stored on this device is erased. You'll need your password to sign back in.")) wipeAndSignOut();
    }
  });
  document.addEventListener("keydown", (e) => {
    if (locked && e.key === "Enter" && e.target?.id === "lockPin") submitPin();
  });
}
