/**
 * sw.js — Service worker for installability + fast repeat loads.
 *
 * IMPORTANT: This only caches the static app shell (HTML/CSS/JS/icons).
 * It deliberately does NOT cache or intercept:
 *   - /api/*        (auth requests must always hit the real server)
 *   - /socket.io/*  (signaling must always be live, never cached)
 * Chat itself still requires a live connection — there is no offline chat,
 * by design, since messages are never stored anywhere.
 */

const CACHE_NAME = "e2ee-chat-shell-v9";
const SHELL_FILES = [
  "/login.html",
  "/login.js",
  "/index.html",
  "/app.js",
  "/messages.html",
  "/messages.js",
  "/messages.css",
  "/crypto.js",
  "/webrtc.js",
  "/config.js",
  "/icons.js",
  "/native.js",
  "/style.css",
  "/manifest.json",
  "/vendor/socket.io.min.js",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Never touch API calls or the socket.io transport - always go live.
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/socket.io/")) {
    return;
  }

  if (event.request.method !== "GET") return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const networkFetch = fetch(event.request)
        .then((response) => {
          if (response && response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => cached);
      return cached || networkFetch;
    })
  );
});
