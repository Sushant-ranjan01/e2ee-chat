/**
 * native.js — One small bridge between the web app and the Android (Capacitor)
 * shell. Every function here is safe to call in a normal browser too: when
 * there's no native plugin it quietly falls back to the web equivalent (or
 * does nothing), so the same code runs in both places.
 *
 * Plugins used (installed via package.json, registered by `npx cap sync`):
 *   @capacitor/app                  hardware Back button + app resume/pause
 *   @capacitor/local-notifications  "new message" / "incoming call" alerts
 *   @capacitor/filesystem + share   save/share received files (blob downloads
 *                                   don't work inside the Android WebView)
 */
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

let notificationsReady = false;
/** Ask for notification permission (Android 13+ shows a system prompt). */
export async function initNotifications() {
  if (notificationsReady) return;
  notificationsReady = true;
  try {
    if (isNative) {
      const LN = plugin("LocalNotifications");
      if (!LN) return;
      await LN.requestPermissions();
      await LN.createChannel?.({ id: "messages", name: "Messages", importance: 4, visibility: 0, vibration: true });
      await LN.createChannel?.({ id: "calls", name: "Incoming calls", importance: 5, visibility: 0, vibration: true });
      LN.addListener("localNotificationActionPerformed", (ev) => tapHandler?.(ev?.notification?.extra || {}));
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
        notifications: [{ id: Math.floor(Math.random() * 2e9), title, body, channelId: channel, extra }],
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
