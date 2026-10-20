import { SERVER_URL } from "./config.js";
import {
  deriveKeyFromPassword,
  unwrapPrivateKey,
  encryptToPublicKey,
  decryptFromPublicKey,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "./crypto.js";
import { ICONS } from "./icons.js";
import { attachMenu, closeMenus } from "./menu.js";
import { initAppLock } from "./applock.js";
import { createKeyring, idbStore } from "./keyring.js";
import { isNative, setBackHandler, onAppState, onNotificationTap, initNotifications, notify, saveBlob, hasPush, reportAppState, unregisterPush, notificationPreviewOn, clearDeliveredPush } from "./native.js";

const $ = (id) => document.getElementById(id);
const MAX_ATTACHMENT_BYTES = 6 * 1024 * 1024; // ~6MB raw (server caps the encrypted/base64 form higher)

// ---------- Auth gate ----------
const token = localStorage.getItem("e2ee_token");
const myUsername = localStorage.getItem("e2ee_username");
const myPublicKey = localStorage.getItem("e2ee_public_key");
if (!token || !myUsername) {
  window.location.href = "/login.html";
}

function logout() {
  unregisterPush(); // must run before the login token is cleared
  localStorage.removeItem("e2ee_token");
  localStorage.removeItem("e2ee_username");
  localStorage.removeItem("e2ee_phone");
  localStorage.removeItem("e2ee_public_key");
  sessionStorage.removeItem("e2ee_privkey_jwk");
  window.location.href = "/login.html";
}
// ---------- Privacy: blocked users (loaded from the server, enforced there too) ----------
let blockedUsers = new Set();
async function loadPrivacy() {
  try {
    const p = await authedFetch("/api/users/me/privacy");
    blockedUsers = new Set(p.blocked || []);
  } catch (err) {
    console.warn("Could not load privacy settings:", err.message);
  }
}
async function blockUser(username) {
  const p = await authedFetch("/api/users/block", { method: "POST", body: JSON.stringify({ username }) });
  blockedUsers = new Set(p.blocked || []);
}
async function unblockUser(username) {
  const p = await authedFetch("/api/users/unblock", { method: "POST", body: JSON.stringify({ username }) });
  blockedUsers = new Set(p.blocked || []);
}

// 3-dot menu in the header: every row has an icon AND text.
attachMenu($("msgMenuBtn"), () => [
  { label: "Settings & privacy", icon: ICONS.settings, href: "settings.html" },
  { label: "New group", icon: ICONS.userPlus, onClick: () => $("newGroupBtn").click() },
  { label: "Quick Room", icon: ICONS.room, href: "index.html" },
  { label: "Log out", icon: ICONS.logout, danger: true, onClick: logout },
]);
$("unlockBackToLogin")?.addEventListener("click", (e) => {
  e.preventDefault();
  logout();
});

initAppLock(); // PIN lock screen (no-op unless the person turned it on)

// ---------- State ----------
let myPrivateKey = null; // CryptoKey, unlocked via password (this session)
let myIdentityJwk = null; // same key as JWK - only used to derive the local vault key (keyring.js)
let ring = null; // on-device one-time keys + encrypted message vault (null = forward secrecy unavailable here)
let socket = null;
/**
 * threadKey = "dm:<username>" or "group:<groupId>"
 * value = { type: 'dm'|'group', peerUsername?, peerPublicKey?, groupId?, name,
 *           members?: [{username,publicKey}] | null (lazily loaded),
 *           messages: [{id, mine, senderUsername, envelope, createdAt}] }
 */
const threads = new Map();
let activeThreadKey = null;
const onlineUsernames = new Set();
/** threadKey -> {timeoutId} - tracks the "X is typing…" indicator per thread */
const typingState = new Map();

// ---------- Unread tracking (per device, stored locally) ----------
// "Unread" = messages from other people newer than the last time this thread
// was open on screen. First run on a device starts from "now", so an old
// account doesn't light up with hundreds of unread chats.
const LASTREAD_KEY = `e2ee_lastread_${myUsername}`;
const BASELINE_KEY = `e2ee_unread_baseline_${myUsername}`;
let lastRead = {};
try { lastRead = JSON.parse(localStorage.getItem(LASTREAD_KEY) || "{}"); } catch { lastRead = {}; }
let unreadBaseline = localStorage.getItem(BASELINE_KEY);
if (!unreadBaseline) {
  unreadBaseline = new Date().toISOString();
  localStorage.setItem(BASELINE_KEY, unreadBaseline);
}

function unreadCount(key) {
  const thread = threads.get(key);
  if (!thread) return 0;
  const since = new Date(lastRead[key] || unreadBaseline).getTime();
  return thread.messages.filter((m) => !m.mine && new Date(m.createdAt).getTime() > since).length;
}
function totalUnread() {
  let n = 0;
  for (const key of threads.keys()) n += unreadCount(key);
  return n;
}
function updateTitleBadge() {
  const n = totalUnread();
  document.title = `${n ? `(${n > 99 ? "99+" : n}) ` : ""}Messages — SecureChat`;
}
function markLocalRead(key) {
  const thread = threads.get(key);
  if (!thread || thread.messages.length === 0) return;
  const latest = thread.messages[thread.messages.length - 1].createdAt;
  if (lastRead[key] === latest) return;
  lastRead[key] = latest;
  try { localStorage.setItem(LASTREAD_KEY, JSON.stringify(lastRead)); } catch { /* storage full - badge just won't persist */ }
  renderConvoList();
  updateTitleBadge();
}

let replyingTo = null; // { id, sender, preview } while composing a reply

function dmKey(username) { return `dm:${username}`; }
function groupKey(groupId) { return `group:${groupId}`; }

async function authedFetch(path, options = {}) {
  const res = await fetch(`${SERVER_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ---------- Unlock private key ----------
async function tryLoadCachedKey() {
  const cachedJwk = sessionStorage.getItem("e2ee_privkey_jwk");
  if (!cachedJwk) return false;
  try {
    myIdentityJwk = JSON.parse(cachedJwk);
    myPrivateKey = await crypto.subtle.importKey(
      "jwk", JSON.parse(cachedJwk), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]
    );
    return true;
  } catch {
    return false;
  }
}

async function showUnlockScreen() {
  $("unlockScreen").classList.remove("hidden");
  $("msgApp").classList.add("hidden");
  const me = await authedFetch("/api/auth/me");

  return new Promise((resolve) => {
    $("unlockBtn").onclick = async () => {
      const password = $("unlockPassword").value;
      $("unlockError").textContent = "";
      if (!password) { $("unlockError").textContent = "Enter your password."; return; }
      $("unlockBtn").disabled = true;
      try {
        const { aesKey } = await deriveKeyFromPassword(password, me.encryptedPrivateKey.salt);
        const privateKey = await unwrapPrivateKey(me.encryptedPrivateKey, aesKey);
        const jwk = await crypto.subtle.exportKey("jwk", privateKey);
        sessionStorage.setItem("e2ee_privkey_jwk", JSON.stringify(jwk));
        myIdentityJwk = jwk;
        myPrivateKey = privateKey;
        $("unlockScreen").classList.add("hidden");
        resolve();
      } catch {
        $("unlockError").textContent = "Incorrect password.";
      } finally {
        $("unlockBtn").disabled = false;
      }
    };
    $("unlockPassword").addEventListener("keydown", (e) => e.key === "Enter" && $("unlockBtn").click());
  });
}

// ---------- Boot ----------
async function boot() {
  const hasKey = await tryLoadCachedKey();
  if (!hasKey) await showUnlockScreen();

  $("meLabel").textContent = myUsername;
  $("msgApp").classList.remove("hidden");

  await initKeyring();
  connectSocket();
  await loadGroups();
  await loadPrivacy();
  await loadInbox();
  renderConvoList();
  updateTitleBadge();
  maintainKeys(true); // after the inbox is saved to the vault: rotate keys, top up one-time keys

  booted = true;
  if (pendingTap) {
    const t = pendingTap;
    pendingTap = null;
    await handleNotificationTap(t);
  }
}

function connectSocket() {
  socket = io(SERVER_URL || undefined, { auth: { token } });
  reportAppState(socket); // tells the server when to use push instead of the live socket

  // ---------- Connection status ----------
  let everConnected = false;
  socket.on("connect", async () => {
    setConnected(true);
    // We may have missed messages / read receipts while disconnected.
    if (everConnected) await refreshInbox();
    everConnected = true;
  });
  socket.on("disconnect", () => setConnected(false));
  socket.on("connect_error", (err) => {
    if (err.message === "unauthorized") logout();
    else setConnected(false);
  });

  socket.on("new-message", async (m) => {
    const fresh = await ingestMessage(m);
    maintainKeys(); // someone just used one of my one-time keys: top the pool up if it's getting low
    const key = threadKeyFor(m);
    const viewing = activeThreadKey === key && !document.hidden;
    if (activeThreadKey === key) renderThread(key);
    if (viewing) markThreadAsRead(key);
    renderConvoList();
    updateTitleBadge();
    if (fresh && !fresh.mine && !viewing) alertNewMessage(key, fresh);
  });

  socket.on("message-deleted", ({ id }) => {
    ring?.vaultDelete(id).catch(() => {});
    for (const [key, thread] of threads.entries()) {
      const idx = thread.messages.findIndex((m) => m.id === id);
      if (idx !== -1) {
        thread.messages.splice(idx, 1);
        if (activeThreadKey === key) renderThread(key);
      }
    }
    renderConvoList();
  });

  // ---------- Presence ----------
  socket.on("presence-snapshot", ({ usernames }) => {
    onlineUsernames.clear();
    usernames.forEach((u) => onlineUsernames.add(u));
    renderConvoList();
    if (activeThreadKey) updateThreadHeaderStatus(activeThreadKey);
  });
  socket.on("presence-online", ({ username }) => {
    onlineUsernames.add(username);
    renderConvoList();
    if (activeThreadKey) updateThreadHeaderStatus(activeThreadKey);
  });
  socket.on("presence-offline", ({ username }) => {
    onlineUsernames.delete(username);
    renderConvoList();
    if (activeThreadKey) updateThreadHeaderStatus(activeThreadKey);
  });

  // ---------- Typing indicator ----------
  socket.on("typing", ({ from }) => {
    // Only show it if it's relevant to the thread currently open.
    const thread = activeThreadKey && threads.get(activeThreadKey);
    if (!thread) return;
    const relevant =
      (thread.type === "dm" && thread.peerUsername === from) ||
      (thread.type === "group" && thread.members?.some((m) => m.username === from));
    if (!relevant) return;

    showTypingIndicator(from);
  });

  // ---------- Direct video calls ----------
  socket.on("incoming-call", (call) => {
    showIncomingCall(call);
    // With push set up, the server already rings the phone when the app isn't in
    // the foreground - a local one too would just be a duplicate.
    if (document.hidden && !hasPush()) {
      notify({ title: "Incoming video call", body: `${call.from} is calling you`, channel: "calls", extra: { type: "call", from: call.from, roomCode: call.roomCode, groupId: call.groupId || "" } });
    }
  });
  socket.on("call-cancelled", ({ roomCode }) => {
    if (incomingCall && incomingCall.roomCode === roomCode) hideIncomingCall();
  });

  // ---------- Someone shared their Quick Room with me ----------
  socket.on("room-invite", ({ from, roomCode }) => {
    showIncomingCall({ from, roomCode, kind: "room" });
    if (document.hidden && !hasPush()) {
      notify({ title: `${from} invited you to a room`, body: "Tap to join the Quick Room", extra: { type: "room-invite", from, roomCode }, channel: "messages" });
    }
  });
  // The room was erased (empty for 2 minutes) - an old invite for it is useless now.
  socket.on("room-expired", ({ roomCode }) => {
    if (incomingCall && incomingCall.roomCode === roomCode) hideIncomingCall();
  });

  // ---------- Read receipts ----------
  socket.on("message-read", ({ id, deliveryStatus }) => {
    for (const [key, thread] of threads.entries()) {
      const msg = thread.messages.find((m) => m.id === id);
      if (msg) {
        msg.deliveryStatus = deliveryStatus;
        if (activeThreadKey === key) renderThread(key);
        break;
      }
    }
  });
}

function threadKeyFor(m) {
  if (m.groupId) return groupKey(m.groupId);
  const peer = m.senderUsername === myUsername ? m.recipientUsername : m.senderUsername;
  return dmKey(peer);
}

async function loadGroups() {
  const data = await authedFetch("/api/groups");
  for (const g of data.groups) {
    const key = groupKey(g.id);
    if (!threads.has(key)) {
      threads.set(key, { type: "group", groupId: g.id, name: g.name, members: null, messages: [] });
    }
  }
}

async function ensureGroupMembers(groupId) {
  const thread = threads.get(groupKey(groupId));
  if (thread.members) return thread.members;
  const data = await authedFetch(`/api/groups/${groupId}`);
  thread.members = data.members; // [{username, publicKey}]
  thread.name = data.name;
  return thread.members;
}

// ---------- Forward secrecy: on-device keys + local history (see keyring.js) ----------
async function initKeyring() {
  try {
    if (!myIdentityJwk?.d || !window.indexedDB) throw new Error("secure storage not available");
    ring = await createKeyring(idbStore("e2ee-keys:" + myUsername), myIdentityJwk);
    await ring.currentEpoch(); // touch the database now so a broken one fails here, not mid-message
  } catch (err) {
    console.warn("Forward secrecy is unavailable on this device:", err.message);
    ring = null; // falls back to the long-term key, exactly like before
  }
}

let lastKeyMaintenance = 0;
/** Rotate the fallback key (daily), top up one-time keys, delete expired old keys. */
async function maintainKeys(force = false) {
  if (!ring) return;
  if (!force && Date.now() - lastKeyMaintenance < 2 * 60 * 1000) return;
  lastKeyMaintenance = Date.now();
  try {
    const status = await authedFetch("/api/keys/status");
    const plan = await ring.plan(status);
    const body = {};
    if (plan.rotateEpoch) body.epoch = await ring.rotateEpoch();
    if (plan.oneTimeToMake) {
      body.oneTimeKeys = await ring.generateOneTimeKeys(plan.oneTimeToMake);
      if (plan.replace) body.replace = true;
    }
    if (Object.keys(body).length) await authedFetch("/api/keys/upload", { method: "POST", body: JSON.stringify(body) });
    await ring.pruneRetired();
  } catch (err) {
    console.warn("Key maintenance failed (will retry):", err.message);
  }
}

/** Ask the server for one-time keys to encrypt to. Falls back to long-term keys if unavailable. */
async function claimKeys(usernames) {
  try {
    const res = await authedFetch("/api/keys/claim", { method: "POST", body: JSON.stringify({ usernames }) });
    return new Map(res.keys.map((k) => [k.username, k]));
  } catch (err) {
    console.warn("Could not get one-time keys, using long-term keys:", err.message);
    return new Map();
  }
}

/** My own copy of a message I send: encrypted to my current rotating key. */
async function encryptForSelf(plaintext) {
  const epoch = ring ? await ring.currentEpoch() : null;
  if (epoch) return { keyId: epoch.id, ...(await encryptToPublicKey(epoch.publicKey, plaintext)) };
  return { keyId: null, ...(await encryptToPublicKey(myPublicKey, plaintext)) };
}

const UNREADABLE_ENVELOPE = {
  type: "text",
  text: "🔒 This message can't be opened on this device. (Its one-time key was already used, or it was sent before this device was set up.)",
};

async function decryptMessage(m) {
  const blob = m.recipientBlob;
  // 1) Already read on this device? It's in the local vault.
  let plaintext = ring ? await ring.vaultGet(m.id) : null;

  // 2) Otherwise decrypt with the key it was sent to, save it, THEN destroy a one-time key.
  if (plaintext == null) {
    try {
      const key = blob.keyId ? await ring?.getPrivate(blob.keyId) : myPrivateKey;
      if (!key) throw new Error("key no longer available");
      plaintext = await decryptFromPublicKey(key, blob.ephemeralPublicKey, blob.iv, blob.ciphertext);
      if (ring) {
        await ring.vaultPut(m.id, plaintext); // saved first - if this throws, the key is kept
        if (blob.keyId) await ring.consume(blob.keyId);
      }
    } catch {
      plaintext = ring ? await ring.vaultGet(m.id) : null; // maybe another tab just did it
      if (plaintext == null) plaintext = JSON.stringify(UNREADABLE_ENVELOPE);
    }
  }
  let envelope;
  try {
    envelope = JSON.parse(plaintext);
  } catch {
    envelope = { type: "text", text: plaintext }; // defensive fallback
  }
  return {
    id: m.id,
    mine: m.senderUsername === myUsername,
    senderUsername: m.senderUsername,
    envelope,
    createdAt: m.createdAt,
    deliveryStatus: m.deliveryStatus || null, // only meaningful when mine === true
    readSent: false, // have I already told the server I've read this one?
  };
}

async function ingestMessage(raw) {
  try {
    const key = threadKeyFor(raw);

    // Already have it? Don't decrypt again - just refresh its read-receipt state.
    const known = threads.get(key)?.messages.find((m) => m.id === raw.id);
    if (known) {
      if (raw.deliveryStatus) known.deliveryStatus = raw.deliveryStatus;
      return null;
    }

    const decrypted = await decryptMessage(raw);
    if (!threads.has(key)) {
      if (raw.groupId) {
        threads.set(key, { type: "group", groupId: raw.groupId, name: "Group", members: null, messages: [] });
      } else {
        const peer = decrypted.mine ? raw.recipientUsername : raw.senderUsername;
        threads.set(key, { type: "dm", peerUsername: peer, peerPublicKey: null, messages: [] });
      }
    }
    const thread = threads.get(key);
    thread.messages.push(decrypted);
    thread.messages.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    return decrypted;
  } catch (err) {
    console.error("Failed to decrypt a message:", err);
    return null;
  }
}

/** Re-fetch everything we might have missed (after reconnecting / returning to the app). */
let refreshing = false;
async function refreshInbox() {
  if (refreshing) return;
  refreshing = true;
  try {
    await loadGroups();
    await loadInbox();
    renderConvoList();
    updateTitleBadge();
    if (activeThreadKey && threads.has(activeThreadKey)) {
      renderThread(activeThreadKey);
      markThreadAsRead(activeThreadKey);
    }
  } catch (err) {
    console.error("Refresh failed:", err);
  } finally {
    refreshing = false;
  }
}

function setConnected(ok) {
  $("connBanner").classList.toggle("hidden", ok && navigator.onLine !== false);
}
window.addEventListener("online", () => { if (socket && !socket.connected) socket.connect(); });
window.addEventListener("offline", () => setConnected(false));

// ---------- Alerts for new messages ----------
let ringCtxBlip = null;
function playBlip() {
  try {
    ringCtxBlip = ringCtxBlip || new (window.AudioContext || window.webkitAudioContext)();
    ringCtxBlip.resume?.();
    const osc = ringCtxBlip.createOscillator();
    const gain = ringCtxBlip.createGain();
    osc.frequency.value = 660;
    gain.gain.setValueAtTime(0.0001, ringCtxBlip.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.1, ringCtxBlip.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, ringCtxBlip.currentTime + 0.18);
    osc.connect(gain).connect(ringCtxBlip.destination);
    osc.start();
    osc.stop(ringCtxBlip.currentTime + 0.2);
  } catch { /* audio blocked - silent is fine */ }
}

function alertNewMessage(key, msg) {
  const thread = threads.get(key);
  const preview = previewFor(msg.envelope).slice(0, 120);
  const title = thread?.type === "group" ? `${msg.senderUsername} · ${thread.name}` : msg.senderUsername;

  if (document.hidden) {
    // Text is only ever put in a notification here, on the phone, after decrypting.
    const body = notificationPreviewOn() ? preview : "New message";
    if (!hasPush()) {
      notify({ title, body, extra: { threadKey: key }, channel: "messages" });
    } else if (notificationPreviewOn()) {
      // The server's push already put a generic "New message" in the tray. Now that
      // the app is awake and has the text, replace it with the real one.
      const groupId = thread?.type === "group" ? thread.groupId : "";
      setTimeout(async () => {
        await clearDeliveredPush((d) => d.type === "message" && d.from === msg.senderUsername && (d.groupId || "") === (groupId || ""));
        notify({ title, body, extra: { threadKey: key }, channel: "messages" });
      }, 1500);
    }
    return;
  }

  // App is open but you're not in that chat: sound + a banner you can tap.
  playBlip();
  navigator.vibrate?.(60);
  showInAppBanner({ title, body: preview, key });
}

let bannerTimer = null;
function showInAppBanner({ title, body, key }) {
  let el = $("inAppBanner");
  if (!el) {
    el = document.createElement("button");
    el.id = "inAppBanner";
    el.className = "in-app-banner hidden";
    document.body.appendChild(el);
  }
  el.innerHTML = "";
  const t = document.createElement("strong");
  t.textContent = title;
  const b = document.createElement("span");
  b.textContent = body;
  el.append(t, b);
  el.onclick = () => { el.classList.add("hidden"); openThread(key); };
  el.classList.remove("hidden");
  clearTimeout(bannerTimer);
  bannerTimer = setTimeout(() => el.classList.add("hidden"), 4500);
}

// A tap can arrive before the inbox has loaded (the app was closed). Hold it
// until boot() finishes, then act on it.
let booted = false;
let pendingTap = null;

async function handleNotificationTap(extra) {
  if (!extra) return;
  if (extra.type === "room-invite" && extra.roomCode) return goToRoom(extra.roomCode);
  if (extra.type === "call" && extra.roomCode) return goToRoom(extra.roomCode, { call: true });
  let key = extra.threadKey;
  if (!key && extra.type === "message") key = extra.groupId ? groupKey(extra.groupId) : dmKey(extra.from);
  if (key && threads.has(key)) await openThread(key);
}

onNotificationTap((extra) => {
  if (!booted) { pendingTap = extra; return; }
  handleNotificationTap(extra);
});

// First tap anywhere: ask for notification permission (browsers require a gesture; Android 13+ prompts here).
document.addEventListener("pointerdown", () => initNotifications(), { once: true });

let hiddenAt = 0;
onAppState((active) => {
  if (!active) { hiddenAt = Date.now(); return; }
  if (socket && !socket.connected) socket.connect();
  if (Date.now() - hiddenAt > 30 * 1000) refreshInbox();
  if (activeThreadKey) markThreadAsRead(activeThreadKey);
});

async function loadInbox() {
  const data = await authedFetch("/api/messages/inbox");
  for (const m of data.messages) await ingestMessage(m);
}

// ---------- Conversation list ----------
function previewFor(envelope) {
  if (!envelope) return "";
  switch (envelope.type) {
    case "text": return envelope.text;
    case "file":
      if (envelope.mimeType?.startsWith("image/")) return "Photo";
      if (envelope.mimeType?.startsWith("video/")) return "Video";
      if (envelope.mimeType?.startsWith("audio/")) return "Voice message";
      return envelope.fileName || "File";
    case "room-invite": return envelope.callType === "video" ? "Video call" : "Quick Room invite";
    default: return "";
  }
}

function renderConvoList() {
  const list = $("convoList");
  list.innerHTML = "";
  const entries = [...threads.entries()].filter(([, t]) => t.messages.length > 0 || t.type === "group");
  entries.sort((a, b) => {
    const at = a[1].messages[a[1].messages.length - 1]?.createdAt || 0;
    const bt = b[1].messages[b[1].messages.length - 1]?.createdAt || 0;
    return new Date(bt) - new Date(at);
  });

  $("noConvos").classList.toggle("hidden", entries.length > 0);

  for (const [key, thread] of entries) {
    const last = thread.messages[thread.messages.length - 1];
    const isGroup = thread.type === "group";
    const label = isGroup ? thread.name : thread.peerUsername;
    const initials = isGroup ? ICONS.users : thread.peerUsername.slice(0, 2).toUpperCase();
    const senderPrefix = isGroup && last && !last.mine ? `${last.senderUsername}: ` : "";
    const online = !isGroup && onlineUsernames.has(thread.peerUsername);
    const unread = unreadCount(key);
    const div = document.createElement("div");
    div.className = "convo-item" + (key === activeThreadKey ? " active" : "") + (unread ? " has-unread" : "");
    div.innerHTML = `
      <div class="avatar">${initials}${isGroup ? "" : `<span class="presence-dot ${online ? "online" : ""}"></span>`}</div>
      <div class="convo-meta">
        <div class="convo-username">${escapeHtml(label)}</div>
        <div class="convo-preview">${escapeHtml(senderPrefix + (last ? previewFor(last.envelope) : "No messages yet"))}</div>
      </div>
      <div class="convo-right">
        <div class="convo-time">${last ? formatTime(last.createdAt) : ""}</div>
        ${unread ? `<span class="unread-badge">${unread > 99 ? "99+" : unread}</span>` : ""}
      </div>
    `;
    div.onclick = () => openThread(key);
    list.appendChild(div);
  }
}

// ---------- Search (for starting a DM) ----------
let searchDebounce = null;
$("searchInput").addEventListener("input", () => {
  clearTimeout(searchDebounce);
  const q = $("searchInput").value.trim().replace(/^@+/, "");
  if (!q) { $("searchResults").classList.add("hidden"); return; }
  searchDebounce = setTimeout(() => runSearch(q), 250);
});

async function runSearch(q) {
  try {
    const data = await authedFetch(`/api/users/search?q=${encodeURIComponent(q)}`);
    const box = $("searchResults");
    box.innerHTML = "";
    if (data.users.length === 0) { box.classList.add("hidden"); return; }
    for (const u of data.users) {
      const div = document.createElement("div");
      div.className = "search-result-item";
      div.innerHTML = `<div class="avatar">${u.username.slice(0, 2).toUpperCase()}</div><div class="convo-username">${u.username}</div>`;
      div.onclick = () => {
        const key = dmKey(u.username);
        if (!threads.has(key)) threads.set(key, { type: "dm", peerUsername: u.username, peerPublicKey: u.publicKey, messages: [] });
        else threads.get(key).peerPublicKey = u.publicKey;
        $("searchInput").value = "";
        box.classList.add("hidden");
        openThread(key);
      };
      box.appendChild(div);
    }
    box.classList.remove("hidden");
  } catch (err) {
    console.error(err);
  }
}

// ---------- New Group ----------
const selectedGroupMembers = new Set();

$("newGroupBtn").onclick = () => {
  selectedGroupMembers.clear();
  $("groupNameInput").value = "";
  $("groupMemberSearch").value = "";
  $("groupMemberChips").innerHTML = "";
  $("groupMemberResults").innerHTML = "";
  $("newGroupPanel").classList.remove("hidden");
};
$("welcomeGroupBtn").onclick = () => $("newGroupBtn").click();
$("cancelGroupBtn").onclick = () => $("newGroupPanel").classList.add("hidden");
$("closeGroupBtn").onclick = () => $("newGroupPanel").classList.add("hidden");

let groupSearchDebounce = null;
$("groupMemberSearch").addEventListener("input", () => {
  clearTimeout(groupSearchDebounce);
  const q = $("groupMemberSearch").value.trim().replace(/^@+/, "");
  if (!q) { $("groupMemberResults").innerHTML = ""; return; }
  groupSearchDebounce = setTimeout(async () => {
    try {
      const data = await authedFetch(`/api/users/search?q=${encodeURIComponent(q)}`);
      const box = $("groupMemberResults");
      box.innerHTML = "";
      for (const u of data.users) {
        if (selectedGroupMembers.has(u.username)) continue;
        const div = document.createElement("div");
        div.className = "search-result-item";
        div.innerHTML = `<div class="avatar">${u.username.slice(0, 2).toUpperCase()}</div><div class="convo-username">${u.username}</div>`;
        div.onclick = () => {
          selectedGroupMembers.add(u.username);
          renderGroupChips();
          $("groupMemberSearch").value = "";
          box.innerHTML = "";
        };
        box.appendChild(div);
      }
    } catch (err) { console.error(err); }
  }, 250);
});

function renderGroupChips() {
  const box = $("groupMemberChips");
  box.innerHTML = "";
  for (const username of selectedGroupMembers) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.innerHTML = `${username} <button data-u="${username}">×</button>`;
    chip.querySelector("button").onclick = () => { selectedGroupMembers.delete(username); renderGroupChips(); };
    box.appendChild(chip);
  }
}

$("createGroupBtn").onclick = async () => {
  const name = $("groupNameInput").value.trim();
  if (!name) return alert("Give the group a name.");
  if (selectedGroupMembers.size === 0) return alert("Add at least one member.");
  try {
    const data = await authedFetch("/api/groups", {
      method: "POST",
      body: JSON.stringify({ name, members: [...selectedGroupMembers] }),
    });
    const key = groupKey(data.group.id);
    threads.set(key, { type: "group", groupId: data.group.id, name: data.group.name, members: null, messages: [] });
    $("newGroupPanel").classList.add("hidden");
    renderConvoList();
    openThread(key);
  } catch (err) {
    alert(err.message);
  }
};

// ---------- Thread view ----------
async function openThread(key) {
  activeThreadKey = key;
  const thread = threads.get(key);

  if (thread.type === "dm" && !thread.peerPublicKey) {
    try {
      const data = await authedFetch(`/api/users/${encodeURIComponent(thread.peerUsername)}`);
      thread.peerPublicKey = data.publicKey;
    } catch (err) {
      alert(err.message);
      return;
    }
  }
  if (thread.type === "group") {
    try {
      await ensureGroupMembers(thread.groupId);
    } catch (err) {
      alert(err.message);
      return;
    }
  }

  $("threadPeerName").textContent = thread.type === "group" ? thread.name : thread.peerUsername;
  $("convoListView").classList.add("hidden");
  $("threadView").classList.remove("hidden");
  $("typingIndicator").classList.add("hidden");
  cancelReply();
  $("emojiPanel").classList.add("hidden");
  renderConvoList();
  updateThreadHeaderStatus(key);
  updateBlockUI(key);
  renderThread(key);
  markThreadAsRead(key);
  if (!isThreadBlocked(key)) $("threadInput").focus();
}

// ---------- Blocking inside a chat ----------
function isThreadBlocked(key) {
  const t = threads.get(key);
  return !!t && t.type === "dm" && blockedUsers.has(t.peerUsername);
}

/** Show/hide the composer, banner, call button and menu according to block state. */
function updateBlockUI(key) {
  const t = threads.get(key);
  if (!t) return;
  const isDm = t.type === "dm";
  const blocked = isThreadBlocked(key);
  $("threadMenuBtn").classList.toggle("hidden", !isDm); // groups have no block menu
  $("threadCallBtn").classList.toggle("hidden", blocked);
  $("threadComposer").classList.toggle("hidden", blocked);
  $("blockedBanner").classList.toggle("hidden", !blocked);
  if (blocked) {
    $("blockedBannerText").textContent = `You blocked @${t.peerUsername}. They can't reach you and won't see when you're online.`;
    $("emojiPanel").classList.add("hidden");
  }
  updateThreadHeaderStatus(key);
}

async function toggleBlock(key) {
  const t = threads.get(key);
  if (!t || t.type !== "dm") return;
  const name = t.peerUsername;
  try {
    if (blockedUsers.has(name)) {
      await unblockUser(name);
      showToast(`Unblocked @${name}.`);
    } else {
      if (!confirm(`Block @${name}?\n\nThey won't be able to message or call you, and won't see your online status. They aren't told that you blocked them.`)) return;
      await blockUser(name);
      showToast(`Blocked @${name}.`);
    }
    updateBlockUI(key);
  } catch (err) {
    alert(err.message);
  }
}

attachMenu($("threadMenuBtn"), () => {
  const t = threads.get(activeThreadKey);
  if (!t || t.type !== "dm") return [];
  const blocked = blockedUsers.has(t.peerUsername);
  return [
    blocked
      ? { label: `Unblock @${t.peerUsername}`, icon: ICONS.shield, onClick: () => toggleBlock(activeThreadKey) }
      : { label: `Block @${t.peerUsername}`, icon: ICONS.block, danger: true, onClick: () => toggleBlock(activeThreadKey) },
    { label: "Settings & privacy", icon: ICONS.settings, href: "settings.html" },
  ];
});
$("unblockBannerBtn").onclick = () => toggleBlock(activeThreadKey);

$("backBtn").onclick = () => {
  activeThreadKey = null;
  cancelReply();
  $("emojiPanel").classList.add("hidden");
  $("threadView").classList.add("hidden");
  $("convoListView").classList.remove("hidden");
  renderConvoList();
};

function updateThreadHeaderStatus(key) {
  const thread = threads.get(key);
  if (!thread) return;
  if (thread.type === "dm" && blockedUsers.has(thread.peerUsername)) {
    $("threadPeerStatus").innerHTML = `<span class="presence-dot"></span> Blocked`;
  } else if (thread.type === "dm") {
    const online = onlineUsernames.has(thread.peerUsername);
    $("threadPeerStatus").innerHTML = `<span class="presence-dot ${online ? "online" : ""}"></span> ${online ? "Online" : "Offline"}`;
  } else {
    const count = thread.members?.length || 0;
    $("threadPeerStatus").textContent = `${count} member${count === 1 ? "" : "s"}`;
  }
}

function showTypingIndicator(fromUsername) {
  clearTimeout(typingState.get(activeThreadKey)?.timeoutId);
  const thread = threads.get(activeThreadKey);
  const label = thread?.type === "group" ? `${fromUsername} is typing…` : "Typing…";
  $("typingLabel").textContent = label;
  $("typingIndicator").classList.remove("hidden");

  const timeoutId = setTimeout(() => {
    $("typingIndicator").classList.add("hidden");
    typingState.delete(activeThreadKey);
  }, 3000);
  typingState.set(activeThreadKey, { timeoutId });
}

async function markThreadAsRead(key) {
  const thread = threads.get(key);
  if (!thread || document.hidden) return; // don't claim "read" while the app is in the background
  markLocalRead(key);
  const unread = thread.messages.filter((m) => !m.mine && !m.readSent);
  if (unread.length === 0) return;
  unread.forEach((m) => (m.readSent = true)); // optimistic - avoid re-sending on rapid re-renders
  try {
    await authedFetch("/api/messages/mark-read", { method: "POST", body: JSON.stringify({ ids: unread.map((m) => m.id) }) });
  } catch (err) {
    console.error("Failed to mark messages read:", err);
  }
}

function renderThread(key) {
  const thread = threads.get(key);
  const container = $("threadMessages");
  container.innerHTML = "";
  for (const m of thread.messages) container.appendChild(renderBubble(m, thread.type === "group"));
  container.scrollTop = container.scrollHeight;
}

function renderBubble(m, showSender) {
  const div = document.createElement("div");
  div.className = `msg-bubble ${m.mine ? "me" : "them"}`;
  div.dataset.id = m.id;

  if (showSender && !m.mine) {
    const sender = document.createElement("div");
    sender.className = "msg-sender";
    sender.textContent = m.senderUsername;
    div.appendChild(sender);
  }

  // Quoted message this one is replying to
  const reply = m.envelope?.replyTo;
  if (reply) {
    const quote = document.createElement("div");
    quote.className = "msg-quote";
    const qName = document.createElement("div");
    qName.className = "msg-quote-name";
    qName.textContent = reply.sender === myUsername ? "You" : reply.sender;
    const qText = document.createElement("div");
    qText.className = "msg-quote-text";
    qText.textContent = reply.preview;
    quote.append(qName, qText);
    quote.onclick = (e) => { e.stopPropagation(); scrollToMessage(reply.id); };
    div.appendChild(quote);
  }

  div.appendChild(renderEnvelopeContent(m.envelope));

  const time = document.createElement("div");
  time.className = "msg-time";
  time.textContent = formatTime(m.createdAt);
  if (m.mine) time.appendChild(renderTicks(m.deliveryStatus));
  div.appendChild(time);

  // Tap (or long-press / right-click) a message for Reply / Copy / Save / Delete.
  // This replaces the old hover-only delete button, which can't work on a touchscreen.
  div.addEventListener("click", (e) => {
    if (e.target.closest("a, button, audio, video, img, .msg-quote")) return;
    showMessageMenu(m, e.clientX, e.clientY);
  });
  div.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    showMessageMenu(m, e.clientX, e.clientY);
  });

  return div;
}

function scrollToMessage(id) {
  const el = $("threadMessages").querySelector(`[data-id="${CSS.escape(String(id))}"]`);
  if (!el) { showToast("That message is no longer here"); return; }
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1200);
}

function renderEnvelopeContent(envelope) {
  const wrap = document.createElement("div");
  if (!envelope) return wrap;

  if (envelope.type === "text") {
    wrap.className = "msg-text";
    wrap.textContent = envelope.text;
    return wrap;
  }

  if (envelope.type === "room-invite") {
    wrap.className = "room-invite";
    const isCall = envelope.callType === "video";
    wrap.innerHTML = `
      <div class="room-invite-label">${isCall ? ICONS.video : ICONS.room}<span>${isCall ? "Video call" : "Quick Room invite"}</span></div>
      <button class="join-room-btn primary">${isCall ? "Join call" : "Join Quick Room"}</button>
    `;
    wrap.querySelector(".join-room-btn").onclick = () => {
      if (isCall) goToRoom(envelope.roomCode, { call: true });
      else goToRoom(envelope.roomCode);
    };
    return wrap;
  }

  if (envelope.type === "file") {
    wrap.className = "msg-text";
    const { blob, url } = mediaFor(envelope);
    if (envelope.mimeType?.startsWith("image/")) {
      const img = document.createElement("img");
      img.src = url;
      img.className = "msg-image";
      img.onclick = () => openLightbox(url, blob, envelope.fileName || "image");
      wrap.appendChild(img);
    } else if (envelope.mimeType?.startsWith("video/")) {
      const video = document.createElement("video");
      video.src = url; video.controls = true;
      wrap.appendChild(video);
    } else if (envelope.mimeType?.startsWith("audio/")) {
      const audio = document.createElement("audio");
      audio.src = url; audio.controls = true;
      wrap.appendChild(audio);
    } else {
      const a = document.createElement("a");
      a.href = url; a.download = envelope.fileName || "file"; a.className = "file-link";
      a.innerHTML = `${ICONS.file}<span>${escapeHtml(envelope.fileName || "Download file")}</span>`;
      // Blob downloads don't work inside the Android WebView - use the share sheet there.
      if (isNative) a.onclick = (e) => { e.preventDefault(); saveBlob(blob, envelope.fileName || "file"); };
      wrap.appendChild(a);
    }
    return wrap;
  }

  wrap.className = "msg-text";
  wrap.textContent = "[Unsupported message]";
  return wrap;
}

// One blob + URL per message (not rebuilt on every re-render - big files on a phone would crawl).
const mediaCache = new WeakMap();
function mediaFor(envelope) {
  let entry = mediaCache.get(envelope);
  if (!entry) {
    const blob = base64ToBlob(envelope.dataBase64, envelope.mimeType);
    entry = { blob, url: URL.createObjectURL(blob) };
    mediaCache.set(envelope, entry);
  }
  return entry;
}

function base64ToBlob(base64, mimeType) {
  const buf = base64ToArrayBuffer(base64);
  return new Blob([buf], { type: mimeType || "application/octet-stream" });
}

// Single grey check = sent (stored on the server). Double blue check = every
// recipient's own client has confirmed they decrypted and displayed it.
function renderTicks(deliveryStatus) {
  const span = document.createElement("span");
  const isRead = !!deliveryStatus?.read;
  span.className = `msg-ticks ${isRead ? "read" : "sent"}`;
  span.title = isRead ? "Read" : "Sent";
  span.innerHTML = isRead
    ? `<svg width="16" height="11" viewBox="0 0 16 11" fill="none"><path d="M1 5.5L5.5 10L10 5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 5.5L10.5 10L15 1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`
    : `<svg width="12" height="11" viewBox="0 0 12 11" fill="none"><path d="M1 5.5L5.5 10L11 1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  return span;
}

// ---------- Message menu (tap / long-press a message) ----------
function closeMessageMenu() {
  $("msgMenu")?.remove();
  $("msgMenuBackdrop")?.remove();
}

function showMessageMenu(m, x, y) {
  closeMessageMenu();
  const items = [{ label: "Reply", icon: ICONS.reply, run: () => startReply(m) }];
  if (m.envelope?.type === "text") {
    items.push({ label: "Copy", icon: ICONS.copy, run: () => copyText(m.envelope.text) });
  }
  if (m.envelope?.type === "file") {
    items.push({ label: isNative ? "Save / share" : "Download", icon: ICONS.download, run: () => saveBlob(mediaFor(m.envelope).blob, m.envelope.fileName || "file") });
  }
  items.push({ label: "Delete for me", icon: ICONS.trash, run: () => deleteMessage(m, "me") });
  items.push({ label: "Delete for everyone", icon: ICONS.trash, danger: true, run: () => deleteMessage(m, "everyone") });

  const backdrop = document.createElement("div");
  backdrop.id = "msgMenuBackdrop";
  backdrop.className = "msg-menu-backdrop";
  backdrop.onclick = closeMessageMenu;
  backdrop.oncontextmenu = (e) => { e.preventDefault(); closeMessageMenu(); };

  const menu = document.createElement("div");
  menu.id = "msgMenu";
  menu.className = "msg-menu";
  for (const item of items) {
    const btn = document.createElement("button");
    btn.className = item.danger ? "danger" : "";
    btn.innerHTML = `${item.icon}<span>${item.label}</span>`;
    btn.onclick = () => { closeMessageMenu(); item.run(); };
    menu.appendChild(btn);
  }
  document.body.append(backdrop, menu);

  // keep it fully on screen
  const w = menu.offsetWidth, h = menu.offsetHeight;
  menu.style.left = `${Math.max(8, Math.min(x, window.innerWidth - w - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(y, window.innerHeight - h - 8))}px`;
}

async function deleteMessage(m, scope) {
  if (scope === "everyone" && !confirm("Delete this message for everyone? This can't be undone.")) return;
  try {
    await authedFetch(`/api/messages/${m.id}`, { method: "DELETE", body: JSON.stringify({ scope }) });
    ring?.vaultDelete(m.id).catch(() => {});
    const thread = threads.get(activeThreadKey);
    const idx = thread.messages.findIndex((x) => x.id === m.id);
    if (idx !== -1) thread.messages.splice(idx, 1);
    renderThread(activeThreadKey);
    renderConvoList();
    updateTitleBadge();
  } catch (err) {
    alert(err.message);
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  showToast("Copied");
}

let toastTimer = null;
function showToast(text) {
  const el = $("toast");
  el.textContent = text;
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 1800);
}

// ---------- Reply ----------
function startReply(m) {
  replyingTo = {
    id: m.id,
    sender: m.senderUsername,
    preview: previewFor(m.envelope).slice(0, 100) || "Message",
  };
  $("replyBarName").textContent = m.mine ? "Replying to yourself" : `Replying to ${m.senderUsername}`;
  $("replyBarText").textContent = replyingTo.preview;
  $("replyBar").classList.remove("hidden");
  $("threadInput").focus();
}
function cancelReply() {
  replyingTo = null;
  $("replyBar")?.classList.add("hidden");
}
$("replyCancelBtn").onclick = cancelReply;

// ---------- Emoji picker ----------
const EMOJIS = ["😀","😁","😂","🤣","😊","😍","😘","😎","🤔","😢","😭","😡","👍","👎","🙏","👏","🔥","🎉","❤️","💯","✅","❌","👀","🙌","💪","🤝","😴","🤗","😅","😉","🙂","🙃","😇","🥳","😜","🤩","😬","😱","🤯","🥰","😋","🫡","✨","⭐","💡","📌","📎","📷","🎵","☕","🍕","🎂","🏆","🚀","🌟","💬"];
const emojiPanel = $("emojiPanel");
for (const emoji of EMOJIS) {
  const span = document.createElement("span");
  span.textContent = emoji;
  span.onclick = () => {
    const input = $("threadInput");
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? start;
    input.value = input.value.slice(0, start) + emoji + input.value.slice(end);
    input.setSelectionRange(start + emoji.length, start + emoji.length);
    input.focus();
  };
  emojiPanel.appendChild(span);
}
$("msgEmojiBtn").onclick = () => emojiPanel.classList.toggle("hidden");

// ---------- Image viewer ----------
let lightboxItem = null;
function openLightbox(url, blob, name) {
  lightboxItem = { blob, name };
  $("lightboxImg").src = url;
  $("lightbox").classList.remove("hidden");
}
function closeLightbox() {
  $("lightbox").classList.add("hidden");
  $("lightboxImg").removeAttribute("src");
  lightboxItem = null;
}
$("lightboxClose").onclick = closeLightbox;
$("lightbox").addEventListener("click", (e) => { if (e.target === $("lightbox")) closeLightbox(); });
$("lightboxSave").onclick = () => lightboxItem && saveBlob(lightboxItem.blob, lightboxItem.name);

// ---------- Android hardware Back button ----------
// Closes the top-most thing first; only when nothing is open does the app minimise.
setBackHandler(() => {
  if (closeMenus()) return true;
  if (!$("lightbox").classList.contains("hidden")) { closeLightbox(); return true; }
  if ($("msgMenu")) { closeMessageMenu(); return true; }
  if (incomingCall) return true; // answer or decline first
  if (!$("newGroupPanel").classList.contains("hidden")) { $("newGroupPanel").classList.add("hidden"); return true; }
  if (!emojiPanel.classList.contains("hidden")) { emojiPanel.classList.add("hidden"); return true; }
  if (replyingTo) { cancelReply(); return true; }
  if (activeThreadKey) { $("backBtn").click(); return true; }
  if (!$("searchResults").classList.contains("hidden")) {
    $("searchResults").classList.add("hidden");
    $("searchInput").value = "";
    return true;
  }
  return false;
});

// ---------- Sending ----------
async function sendEnvelope(envelope) {
  const thread = threads.get(activeThreadKey);
  if (!thread) return false;
  if (isThreadBlocked(activeThreadKey)) { showToast("Unblock this person to send messages."); return false; }

  // Attach the message being replied to (a short preview, encrypted along with the message itself).
  if (replyingTo && envelope.type !== "room-invite") {
    envelope = { ...envelope, replyTo: replyingTo };
  }

  try {
    let body;
    const plaintext = JSON.stringify(envelope);
    if (thread.type === "group") {
      const members = await ensureGroupMembers(thread.groupId);
      const others = members.filter((mem) => mem.username !== myUsername).map((mem) => mem.username);
      const claims = others.length ? await claimKeys(others) : new Map();
      const recipients = [];
      for (const member of members) {
        if (member.username === myUsername) {
          recipients.push({ username: myUsername, ...(await encryptForSelf(plaintext)) });
          continue;
        }
        const c = claims.get(member.username);
        const enc = await encryptToPublicKey(c?.publicKey || member.publicKey, plaintext);
        recipients.push({ username: member.username, keyId: c?.keyId || null, ...enc });
      }
      body = { groupId: thread.groupId, recipients };
    } else {
      const claim = (await claimKeys([thread.peerUsername])).get(thread.peerUsername);
      const forRecipient = await encryptToPublicKey(claim?.publicKey || thread.peerPublicKey, plaintext);
      body = {
        recipientUsername: thread.peerUsername,
        recipients: [
          { username: thread.peerUsername, keyId: claim?.keyId || null, ...forRecipient },
          { username: myUsername, ...(await encryptForSelf(plaintext)) },
        ],
      };
    }

    const res = await authedFetch("/api/messages/send", { method: "POST", body: JSON.stringify(body) });
    await ring?.vaultPut(res.message.id, plaintext).catch(() => {}); // keep my own sent message readable locally
    await ingestMessage(res.message);
    if (envelope.replyTo) cancelReply();
    renderThread(activeThreadKey);
    markLocalRead(activeThreadKey);
    renderConvoList();
    return true;
  } catch (err) {
    alert(err.message);
    return false;
  }
}

$("threadSendBtn").onclick = sendThreadText;
$("threadInput").addEventListener("keydown", (e) => e.key === "Enter" && sendThreadText());

let lastTypingEmit = 0;
$("threadInput").addEventListener("input", () => {
  if (!activeThreadKey) return;
  const now = Date.now();
  if (now - lastTypingEmit < 1500) return; // throttle - no need to spam this on every keystroke
  lastTypingEmit = now;

  const thread = threads.get(activeThreadKey);
  if (!thread) return;
  const to =
    thread.type === "group"
      ? (thread.members || []).map((m) => m.username).filter((u) => u !== myUsername)
      : thread.peerUsername;
  if (to && (Array.isArray(to) ? to.length > 0 : true)) {
    socket.emit("typing", { to });
  }
});

async function sendThreadText() {
  const text = $("threadInput").value.trim();
  if (!text || !activeThreadKey) return;
  $("threadInput").value = "";
  $("emojiPanel").classList.add("hidden");
  await sendEnvelope({ type: "text", text });
}

// ---------- File attachments ----------
$("msgFileBtn").onclick = () => $("msgFileInput").click();
$("msgFileInput").onchange = async (e) => {
  for (const file of e.target.files) await sendFileEnvelope(file);
  $("msgFileInput").value = "";
};

async function sendFileEnvelope(file) {
  if (file.size > MAX_ATTACHMENT_BYTES) {
    alert(`That file is too large (max ${(MAX_ATTACHMENT_BYTES / 1024 / 1024).toFixed(0)}MB).`);
    return;
  }
  const buf = await file.arrayBuffer();
  const dataBase64 = arrayBufferToBase64(buf);
  await sendEnvelope({
    type: "file",
    fileName: file.name,
    mimeType: file.type || "application/octet-stream",
    dataBase64,
  });
}

// ---------- Voice messages ----------
let mediaRecorder = null;
let recordedChunks = [];
let recordingStream = null;

$("msgVoiceBtn").onclick = async () => {
  try {
    recordingStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    recordedChunks = [];
    mediaRecorder = new MediaRecorder(recordingStream);
    mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) recordedChunks.push(e.data); };
    mediaRecorder.start();
    $("msgRecordingBar").classList.remove("hidden");
  } catch (err) {
    alert("Couldn't access microphone: " + err.message);
  }
};
$("msgCancelRecordBtn").onclick = () => stopVoiceRecording(false);
$("msgStopRecordBtn").onclick = () => stopVoiceRecording(true);

function stopVoiceRecording(send) {
  if (!mediaRecorder) return;
  mediaRecorder.onstop = async () => {
    recordingStream?.getTracks().forEach((t) => t.stop());
    $("msgRecordingBar").classList.add("hidden");
    if (send && recordedChunks.length) {
      const blob = new Blob(recordedChunks, { type: "audio/webm" });
      const file = new File([blob], `voice-message-${Date.now()}.webm`, { type: "audio/webm" });
      await sendFileEnvelope(file);
    }
    mediaRecorder = null;
  };
  mediaRecorder.stop();
}

// ---------- Share Quick Room ----------
function generateRoomCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

$("msgShareRoomBtn").onclick = async () => {
  const code = generateRoomCode();
  const sent = await sendEnvelope({ type: "room-invite", roomCode: code });
  if (sent === false) return;
  goToRoom(code, { create: true });
};

// ---------- Direct video call (from a chat thread) ----------
// Opens the Quick Room page with the camera starting automatically. The room
// IS the call: same peer-to-peer, end-to-end encrypted mesh as a Quick Room.
function goToRoom(code, { call = false, create = false } = {}) {
  const params = new URLSearchParams({ room: code, from: "messages" });
  if (call) params.set("call", "video");
  if (create) params.set("create", "1"); // only the person who starts a room may create it
  window.location.href = `index.html?${params.toString()}`;
}

$("threadCallBtn").onclick = async () => {
  const thread = threads.get(activeThreadKey);
  if (!thread) return;
  const btn = $("threadCallBtn");
  btn.disabled = true;
  try {
    const code = generateRoomCode();
    // 1) Post an end-to-end encrypted "Video call" invite into the thread
    //    (it stays in the chat, so the other side can join late / see missed calls).
    const sent = await sendEnvelope({ type: "room-invite", roomCode: code, callType: "video" });
    if (!sent) return;

    // 2) Ring everyone who's online right now.
    const to =
      thread.type === "group"
        ? (thread.members || []).map((m) => m.username).filter((u) => u !== myUsername)
        : [thread.peerUsername];
    let navigated = false;
    const go = () => { if (!navigated) { navigated = true; goToRoom(code, { call: true, create: true }); } };
    socket.emit("call-invite", { to, roomCode: code, callType: "video", groupId: thread.groupId }, go);
    setTimeout(go, 1500); // don't get stuck if the ack never arrives
  } finally {
    btn.disabled = false;
  }
};

// ---------- Incoming call ring ----------
let incomingCall = null; // { from, roomCode, groupId }
let ringTimer = null;
let ringInterval = null;
let ringCtx = null;

function playRingBurst() {
  try {
    ringCtx = ringCtx || new (window.AudioContext || window.webkitAudioContext)();
    ringCtx.resume?.();
    [0, 0.25].forEach((offset) => {
      const osc = ringCtx.createOscillator();
      const gain = ringCtx.createGain();
      osc.frequency.value = 880;
      gain.gain.setValueAtTime(0.0001, ringCtx.currentTime + offset);
      gain.gain.exponentialRampToValueAtTime(0.15, ringCtx.currentTime + offset + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, ringCtx.currentTime + offset + 0.2);
      osc.connect(gain).connect(ringCtx.destination);
      osc.start(ringCtx.currentTime + offset);
      osc.stop(ringCtx.currentTime + offset + 0.22);
    });
  } catch { /* audio may be blocked until the user interacts - the visual ring still shows */ }
  navigator.vibrate?.([300, 150, 300]);
}

function showIncomingCall(call) {
  hideIncomingCall();
  incomingCall = call;
  const group = call.groupId ? threads.get(groupKey(call.groupId)) : null;
  $("incomingCallAvatar").textContent = call.from.slice(0, 2).toUpperCase();
  $("incomingCallTitle").textContent = call.from;
  const isRoom = call.kind === "room";
  $("incomingCallSub").textContent = isRoom
    ? "Invited you to a Quick Room"
    : group ? `Incoming video call · ${group.name}` : "Incoming video call";
  $("incomingCall").classList.remove("hidden");
  if (isRoom) {
    playBlip(); // an invite is a nudge, not a ringing phone
  } else {
    playRingBurst();
    ringInterval = setInterval(playRingBurst, 2500);
  }
  ringTimer = setTimeout(hideIncomingCall, isRoom ? 60 * 1000 : 30 * 1000); // stop if nobody answers
}

function hideIncomingCall() {
  clearInterval(ringInterval);
  clearTimeout(ringTimer);
  ringInterval = ringTimer = null;
  incomingCall = null;
  $("incomingCall")?.classList.add("hidden");
}

$("acceptCallBtn").onclick = () => {
  if (!incomingCall) return;
  const { roomCode, kind } = incomingCall;
  hideIncomingCall();
  goToRoom(roomCode, { call: kind !== "room" });
};
$("declineCallBtn").onclick = () => {
  if (incomingCall && incomingCall.kind !== "room") socket?.emit("call-decline", { roomCode: incomingCall.roomCode });
  hideIncomingCall();
};

// ---------- Helpers ----------
function formatTime(iso) {
  const d = new Date(iso);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}
function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

boot();
