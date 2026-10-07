/**
 * config.js — Where the app finds its backend.
 *
 * On the WEB (opened directly in a browser at your server's URL), the
 * frontend and backend share an origin, so leaving SERVER_URL empty works
 * fine — requests just go to "wherever this page came from".
 *
 * In the NATIVE APP (Capacitor/Android), the frontend files are bundled
 * *inside* the app itself — there is no "same server" to fall back to.
 * Every request has to name your deployed backend explicitly.
 *
 * >>> Before building the Android APK, set this to your deployed backend's
 * >>> full URL, e.g. "https://your-app-name.onrender.com" — then rebuild.
 */
// Default backend. Leave "" to use the page's own origin (web), or hardcode your
// deployed URL here. In the native app you can ALSO set it at runtime from the
// login screen ("Server settings") - that saved value wins, so the same APK
// can be pointed at a different server without rebuilding.
const DEFAULT_SERVER_URL = ""; // e.g. "https://your-backend.example.com"

const SERVER_URL_KEY = "e2ee_server_url";
function readStoredServerUrl() {
  try { return localStorage.getItem(SERVER_URL_KEY) || ""; } catch { return ""; }
}
export const SERVER_URL = (readStoredServerUrl() || DEFAULT_SERVER_URL).replace(/\/+$/, "");

/** Save (or clear, with "") the server address used from now on. */
export function setServerUrl(url) {
  const clean = String(url || "").trim().replace(/\/+$/, "");
  if (clean) localStorage.setItem(SERVER_URL_KEY, clean);
  else localStorage.removeItem(SERVER_URL_KEY);
}

// True when running inside the Capacitor native shell (Android/iOS),
// false in a normal browser tab.
export const isNativeApp = typeof window !== "undefined" && !!window.Capacitor?.isNativePlatform?.();
