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
export const SERVER_URL = ""; // e.g. "https://your-backend.example.com"

// True when running inside the Capacitor native shell (Android/iOS),
// false in a normal browser tab.
export const isNativeApp = typeof window !== "undefined" && !!window.Capacitor?.isNativePlatform?.();
