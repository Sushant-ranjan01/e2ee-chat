/**
 * native.js — One small bridge between the web app and the Android (Capacitor)
 * shell. Every function here is safe to call in a normal browser too: when
 * there's no native plugin it quietly falls back to the web equivalent (or
 * does nothing), so the same code runs in both places.
 *
 * Plugins used (installed via package.json, registered by `npx cap sync`):
 *   @capacitor/app                  hardware Back button + app resume/pause
 *   @capacitor/local-notifications  "new message" / "incoming call" alerts while the app is open
 *   @capacitor/push-notifications   the same alerts when the app is CLOSED (Firebase Cloud Messaging)
 *   @capacitor/filesystem + share   save/share received files (blob downloads
 *                                   don't work inside the Android WebView)
 */
import { SERVER_URL } from "./config.js";

const cap = typeof window !== "undefined" ? window.Capacitor : null;
export const isNative = !!cap?.isNativePlatform?.();
const plugin = (name) => cap?.Plugins?.[name];

// ---------- Hardware Back button ----------
// A page registers ONE handler. Return true if it handled the press (closed a
// panel, left a thread...). Return false/undefined and the app minimises, the
// way messaging apps behave, instead of backing out into the login page.
let backHandler = null;
export function setBackHandler(fn) {
  backHandler = fn;
}
if (isNative) {
  plugin("App")?.addListener?.("backButton", () => {
    let handled = false;
    try { handled = backHandler?.() === true; } catch (err) { console.error(err); }
    if (!handled) plugin("App")?.minimizeApp?.();
  });
}

// ---------- App foreground / background ----------
// fn(true) when the app comes to the foreground, fn(false) when it leaves.
// Fires only on actual changes (the web and native signals can overlap).
export function onAppState(fn) {
  let last = !document.hidden;
  const emit = (active) => {
    if (active === last) return;
    last = active;
    fn(active);
  };
  document.addEventListener("visibilitychange", () => emit(!document.hidden));
  plugin("App")?.addListener?.("appStateChange", ({ isActive }) => emit(!!isActive));
}

// ---------- Notifications ----------
let tapHandler = null;
export function onNotificationTap(fn) {
  tapHandler = fn;
}

// Talks to this app's own backend to bind / unbind this phone's push token.
const PUSH_TOKEN_KEY = "e2ee_push_token";
const pushApi = {
  async register(pushToken) {
    const r = await fetch(`${SERVER_URL}/api/push/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("e2ee_token")}` },
      body: JSON.stringify({ token: pushToken }),
    });
    if (!r.ok) throw new Error("push register failed (" + r.status + ")");
    return r.json();
  },
  async unregister(pushToken) {
    await fetch(`${SERVER_URL}/api/push/unregister`, {
      method: "POST",
      keepalive: true, // still goes out while the page is navigating to the login screen
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("e2ee_token")}` },
      body: JSON.stringify({ token: pushToken }),
    });
  },
};

// True once this phone is registered for push AND the server can actually send
// it. While true, the server (not this device) raises "new message" alerts for
// the background/closed case, so we skip the local one to avoid duplicates.
let pushActive = false;
export function hasPush() { return pushActive; }
let currentPushToken = null;

/**
 * Register this phone for push. `registerToken(token)` should send the token
 * to the server (POST /api/push/register) and resolve to { serverPush }.
 */
async function initPush(registerToken) {
  const PN = plugin("PushNotifications");
  if (!PN || !registerToken) return;
  try {
    const perm = await PN.requestPermissions();
    if (perm?.receive !== "granted") return;
    await PN.addListener("registration", async ({ value }) => {
      currentPushToken = value;
      try { localStorage.setItem(PUSH_TOKEN_KEY, value); } catch { /* ignore */ }
      try {
        const res = await registerToken(value);
        pushActive = !!res?.serverPush;
      } catch (err) {
        console.warn("Could not register push token:", err);
      }
    });
    await PN.addListener("registrationError", (err) => console.warn("Push registration failed:", err));
    // Tapped a push (app was closed or in the background).
    await PN.addListener("pushNotificationActionPerformed", (ev) => tapHandler?.(ev?.notification?.data || {}));
    // A push that arrives while the app is open is ignored: the live socket already showed it.
    await PN.register();
  } catch (err) {
    console.warn("Push unavailable (is google-services.json in android/app?):", err);
  }
}

/** Stop pushes for this account on this phone. Call on logout, BEFORE the
 *  login token is cleared (the server needs it to know whose token to drop). */
export function unregisterPush() {
  if (!isNative) return;
  let stored = null;
  try { stored = localStorage.getItem(PUSH_TOKEN_KEY); localStorage.removeItem(PUSH_TOKEN_KEY); } catch { /* ignore */ }
  const t = currentPushToken || stored;
  pushActive = false;
  currentPushToken = null;
  if (t) pushApi.unregister(t).catch(() => {});
  try { plugin("PushNotifications")?.unregister?.(); } catch { /* ignore */ }
}

/** Tell the server whether this app is in the foreground, so it knows when a
 *  push is needed (background) and when the live socket is enough (foreground). */
export function reportAppState(sock) {
  const send = (active) => { if (sock?.connected) sock.emit("app-state", { active }); };
  onAppState(send);
  sock.on("connect", () => send(!document.hidden));
}

let notificationsReady = false;
/** Ask for notification permission (Android 13+ shows a system prompt).
 *  On the Android app this also turns on push notifications (the closed-app case). */
export async function initNotifications({ registerToken = pushApi.register } = {}) {
  if (notificationsReady) return;
  notificationsReady = true;
  try {
    if (isNative) {
      const LN = plugin("LocalNotifications");
      if (LN) {
        await LN.requestPermissions();
        await LN.createChannel?.({ id: "messages", name: "Messages", importance: 4, visibility: 0, vibration: true });
        await LN.createChannel?.({ id: "calls", name: "Incoming calls", importance: 5, visibility: 0, vibration: true });
        LN.addListener("localNotificationActionPerformed", (ev) => tapHandler?.(ev?.notification?.extra || {}));
      }
      // Channels must exist BEFORE the first push arrives (created above).
      await initPush(registerToken);
    } else if ("Notification" in window && Notification.permission === "default") {
      await Notification.requestPermission();
    }
  } catch (err) {
    console.warn("Notifications unavailable:", err);
  }
}

/** Show a system notification. The text is built on THIS device after
 *  decryption - the server never sees message content, even for alerts. */
export async function notify({ title, body, extra = {}, channel = "messages" }) {
  try {
    if (isNative) {
      await plugin("LocalNotifications")?.schedule({
        notifications: [{
          id: Math.floor(Math.random() * 2e9), title, body, channelId: channel, extra,
          smallIcon: "ic_stat_chat", iconColor: "#5682B1",
          // One stack per chat, like other messaging apps.
          ...(extra.threadKey ? { group: extra.threadKey } : {}),
        }],
      });
    } else if ("Notification" in window && Notification.permission === "granted") {
      const n = new Notification(title, { body, icon: "/icons/icon-192.png", tag: extra.threadKey });
      n.onclick = () => { window.focus(); tapHandler?.(extra); n.close(); };
    }
  } catch (err) {
    console.warn("Could not show notification:", err);
  }
}

// ---------- Save / share a file ----------
function blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1]);
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
}

/** Native: opens the Android share sheet (save to Drive/Files, send to other
 *  apps...). Browser: a normal download. */
export async function saveBlob(blob, fileName) {
  const name = (fileName || "file").replace(/[^\w.\- ]+/g, "_");
  if (isNative && plugin("Filesystem") && plugin("Share")) {
    try {
      const data = await blobToBase64(blob);
      const { uri } = await plugin("Filesystem").writeFile({ path: name, data, directory: "CACHE" });
      await plugin("Share").share({ title: name, url: uri, dialogTitle: "Save or share" });
      return;
    } catch (err) {
      if (/cancel/i.test(String(err))) return; // user closed the share sheet
      console.error("Native save failed, falling back:", err);
    }
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ---------- Screen privacy + fingerprint (local plugin: AppSecurityPlugin.java) ----------
/** Block screenshots / screen recording and hide the recent-apps preview. No-op in a browser. */
export async function setSecureScreen(enabled) {
  if (!isNative) return;
  try { await plugin("AppSecurity")?.setSecure?.({ enabled: !!enabled }); } catch { /* ignore */ }
}

export async function biometricAvailable() {
  if (!isNative) return false;
  try { return !!(await plugin("AppSecurity")?.biometricAvailable?.())?.available; } catch { return false; }
}

/** Show the system fingerprint prompt. Resolves true only if the person passed it. */
export async function biometricAuth({ title = "Unlock", subtitle = "", cancel = "Use PIN" } = {}) {
  if (!isNative) return false;
  try { return !!(await plugin("AppSecurity")?.authenticate?.({ title, subtitle, cancel }))?.ok; } catch { return false; }
}

// ---------- Notification preferences + helpers ----------
const PREVIEW_KEY = "e2ee_notif_preview";
/** Show the message text in system notifications? (default yes; text is built on the phone, never sent through Google) */
export function notificationPreviewOn() { return localStorage.getItem(PREVIEW_KEY) !== "0"; }
export function setNotificationPreview(on) { localStorage.setItem(PREVIEW_KEY, on ? "1" : "0"); }

/** Remove push notifications already in the tray that match (used to swap a generic
 *  "New message" push for the detailed one once the app can decrypt the text). */
export async function clearDeliveredPush(match) {
  try {
    const PN = plugin("PushNotifications");
    if (!PN?.getDeliveredNotifications) return;
    const { notifications = [] } = await PN.getDeliveredNotifications();
    const hit = notifications.filter((x) => match(x.data || {}, x));
    if (hit.length) await PN.removeDeliveredNotifications({ notifications: hit });
  } catch { /* best effort */ }
}
