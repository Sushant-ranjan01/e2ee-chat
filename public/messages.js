import { SERVER_URL } from "./config.js";
import { deriveKeyFromPassword, unwrapPrivateKey, encryptToPublicKey, decryptFromPublicKey } from "./crypto.js";

const $ = (id) => document.getElementById(id);

// ---------- Auth gate ----------
const token = localStorage.getItem("e2ee_token");
const myUsername = localStorage.getItem("e2ee_username");
const myPublicKey = localStorage.getItem("e2ee_public_key");
if (!token || !myUsername) {
  window.location.href = "/login.html";
}

function logout() {
  localStorage.removeItem("e2ee_token");
  localStorage.removeItem("e2ee_username");
  localStorage.removeItem("e2ee_phone");
  localStorage.removeItem("e2ee_public_key");
  sessionStorage.removeItem("e2ee_privkey_jwk");
  window.location.href = "/login.html";
}
$("msgLogoutBtn")?.addEventListener("click", logout);

// ---------- State ----------
let myPrivateKey = null; // CryptoKey, unlocked via password (this session)
let socket = null;
/** peerUsername -> { peerPublicKey, messages: [{id, mine, text, createdAt}] } */
const threads = new Map();
let activeThreadPeer = null;

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
    myPrivateKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(cachedJwk),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
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
      if (!password) {
        $("unlockError").textContent = "Enter your password.";
        return;
      }
      $("unlockBtn").disabled = true;
      try {
        const { aesKey } = await deriveKeyFromPassword(password, me.encryptedPrivateKey.salt);
        const privateKey = await unwrapPrivateKey(me.encryptedPrivateKey, aesKey);
        const jwk = await crypto.subtle.exportKey("jwk", privateKey);
        sessionStorage.setItem("e2ee_privkey_jwk", JSON.stringify(jwk));
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

  $("meLabel").textContent = `@${myUsername}`;
  $("msgApp").classList.remove("hidden");

  connectSocket();
  await loadInbox();
  renderConvoList();
}

function connectSocket() {
  socket = io(SERVER_URL || undefined, { auth: { token } });
  socket.on("new-message", async (m) => {
    await ingestMessage(m);
    renderConvoList();
    if (activeThreadPeer && (m.senderUsername === activeThreadPeer || m.recipientUsername === activeThreadPeer)) {
      renderThread(activeThreadPeer);
    }
  });
  socket.on("message-deleted", ({ id }) => {
    for (const thread of threads.values()) {
      const idx = thread.messages.findIndex((m) => m.id === id);
      if (idx !== -1) thread.messages.splice(idx, 1);
    }
    renderConvoList();
    if (activeThreadPeer) renderThread(activeThreadPeer);
  });
}

async function decryptMessage(m) {
  const mine = m.senderUsername === myUsername;
  const blob = mine ? m.forSender : m.forRecipient;
  const text = await decryptFromPublicKey(myPrivateKey, blob.ephemeralPublicKey, blob.iv, blob.ciphertext);
  return { id: m.id, mine, text, createdAt: m.createdAt, peer: mine ? m.recipientUsername : m.senderUsername };
}

async function ingestMessage(raw) {
  try {
    const decrypted = await decryptMessage(raw);
    const peer = decrypted.peer;
    if (!threads.has(peer)) threads.set(peer, { peerPublicKey: null, messages: [] });
    const thread = threads.get(peer);
    if (!thread.messages.find((m) => m.id === decrypted.id)) {
      thread.messages.push(decrypted);
      thread.messages.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    }
  } catch (err) {
    console.error("Failed to decrypt a message:", err);
  }
}

async function loadInbox() {
  const data = await authedFetch("/api/messages/inbox");
  for (const m of data.messages) {
    await ingestMessage(m);
  }
}

// ---------- Conversation list ----------
function renderConvoList() {
  const list = $("convoList");
  list.innerHTML = "";
  const entries = [...threads.entries()].filter(([, t]) => t.messages.length > 0);
  entries.sort((a, b) => {
    const at = a[1].messages[a[1].messages.length - 1]?.createdAt || 0;
    const bt = b[1].messages[b[1].messages.length - 1]?.createdAt || 0;
    return new Date(bt) - new Date(at);
  });

  $("noConvos").classList.toggle("hidden", entries.length > 0);

  for (const [peer, thread] of entries) {
    const last = thread.messages[thread.messages.length - 1];
    const div = document.createElement("div");
    div.className = "convo-item";
    div.innerHTML = `
      <div class="avatar">${peer.slice(0, 2).toUpperCase()}</div>
      <div class="convo-meta">
        <div class="convo-username">@${peer}</div>
        <div class="convo-preview">${last ? escapeHtml(last.text) : ""}</div>
      </div>
      <div class="convo-time">${last ? formatTime(last.createdAt) : ""}</div>
    `;
    div.onclick = () => openThread(peer);
    list.appendChild(div);
  }
}

// ---------- Search ----------
let searchDebounce = null;
$("searchInput").addEventListener("input", () => {
  clearTimeout(searchDebounce);
  const q = $("searchInput").value.trim();
  if (!q) {
    $("searchResults").classList.add("hidden");
    return;
  }
  searchDebounce = setTimeout(() => runSearch(q), 250);
});

async function runSearch(q) {
  try {
    const data = await authedFetch(`/api/users/search?q=${encodeURIComponent(q)}`);
    const box = $("searchResults");
    box.innerHTML = "";
    if (data.users.length === 0) {
      box.classList.add("hidden");
      return;
    }
    for (const u of data.users) {
      const div = document.createElement("div");
      div.className = "search-result-item";
      div.innerHTML = `<div class="avatar">${u.username.slice(0, 2).toUpperCase()}</div><div class="convo-username">@${u.username}</div>`;
      div.onclick = () => {
        if (!threads.has(u.username)) threads.set(u.username, { peerPublicKey: u.publicKey, messages: [] });
        else threads.get(u.username).peerPublicKey = u.publicKey;
        $("searchInput").value = "";
        box.classList.add("hidden");
        openThread(u.username);
      };
      box.appendChild(div);
    }
    box.classList.remove("hidden");
  } catch (err) {
    console.error(err);
  }
}

// ---------- Thread view ----------
async function openThread(peer) {
  activeThreadPeer = peer;
  if (!threads.has(peer)) threads.set(peer, { peerPublicKey: null, messages: [] });
  const thread = threads.get(peer);
  if (!thread.peerPublicKey) {
    try {
      const data = await authedFetch(`/api/users/${encodeURIComponent(peer)}`);
      thread.peerPublicKey = data.publicKey;
    } catch (err) {
      alert(err.message);
      return;
    }
  }

  $("threadPeerName").textContent = `@${peer}`;
  $("convoListView").classList.add("hidden");
  $("threadView").classList.remove("hidden");
  renderThread(peer);
  $("threadInput").focus();
}

$("backBtn").onclick = () => {
  activeThreadPeer = null;
  $("threadView").classList.add("hidden");
  $("convoListView").classList.remove("hidden");
  renderConvoList();
};

function renderThread(peer) {
  const thread = threads.get(peer);
  const container = $("threadMessages");
  container.innerHTML = "";
  for (const m of thread.messages) {
    container.appendChild(renderBubble(m));
  }
  container.scrollTop = container.scrollHeight;
}

function renderBubble(m) {
  const div = document.createElement("div");
  div.className = `msg-bubble ${m.mine ? "me" : "them"}`;
  div.innerHTML = `
    <div class="msg-text"></div>
    <div class="msg-time">${formatTime(m.createdAt)}</div>
    <button class="msg-delete-btn" title="Delete">🗑</button>
  `;
  div.querySelector(".msg-text").textContent = m.text; // textContent - never render as HTML
  div.querySelector(".msg-delete-btn").onclick = (e) => {
    e.stopPropagation();
    showDeleteMenu(e.currentTarget, m);
  };
  return div;
}

function showDeleteMenu(anchor, m) {
  document.querySelectorAll(".delete-menu").forEach((el) => el.remove());
  const menu = document.createElement("div");
  menu.className = "delete-menu";
  menu.innerHTML = `
    <button data-scope="me">Delete for me</button>
    <button data-scope="everyone" class="danger">Delete for everyone</button>
  `;
  document.body.appendChild(menu);
  const rect = anchor.getBoundingClientRect();
  menu.style.top = `${rect.bottom + window.scrollY + 4}px`;
  menu.style.left = `${Math.min(rect.left + window.scrollX, window.innerWidth - 180)}px`;

  menu.querySelectorAll("button").forEach((btn) => {
    btn.onclick = async () => {
      menu.remove();
      try {
        await authedFetch(`/api/messages/${m.id}`, { method: "DELETE", body: JSON.stringify({ scope: btn.dataset.scope }) });
        const thread = threads.get(activeThreadPeer);
        const idx = thread.messages.findIndex((x) => x.id === m.id);
        if (idx !== -1) thread.messages.splice(idx, 1);
        renderThread(activeThreadPeer);
        renderConvoList();
      } catch (err) {
        alert(err.message);
      }
    };
  });

  setTimeout(() => {
    document.addEventListener("click", function closeOnce() {
      menu.remove();
      document.removeEventListener("click", closeOnce);
    });
  }, 0);
}

$("threadSendBtn").onclick = sendThreadMessage;
$("threadInput").addEventListener("keydown", (e) => e.key === "Enter" && sendThreadMessage());

async function sendThreadMessage() {
  const text = $("threadInput").value.trim();
  if (!text || !activeThreadPeer) return;
  const thread = threads.get(activeThreadPeer);
  if (!thread.peerPublicKey) return;

  $("threadInput").value = "";
  try {
    const forRecipient = await encryptToPublicKey(thread.peerPublicKey, text);
    const forSender = await encryptToPublicKey(myPublicKey, text);
    const res = await authedFetch("/api/messages/send", {
      method: "POST",
      body: JSON.stringify({ recipientUsername: activeThreadPeer, forRecipient, forSender }),
    });
    await ingestMessage(res.message);
    renderThread(activeThreadPeer);
    renderConvoList();
  } catch (err) {
    alert(err.message);
  }
}

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
