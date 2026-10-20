import { isNativeApp } from "./config.js";
if ("serviceWorker" in navigator && !isNativeApp) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js"));
}
