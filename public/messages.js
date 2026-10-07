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
import { CallManager } from "./call.js";

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
  localStorage.removeItem("e2ee_token");
  localStorage.removeItem("e2ee_username");
  localStorage.removeItem("e2ee_phone");
  localStorage.removeItem("e2ee_public_key");
  sessionStorage.removeItem("e2ee_privkey_jwk");
  window.location.href = "/login.html";
}
$("msgLogoutBtn")?.addEventListener("click", logout);
$("unlockBackToLogin")?.addEventListener("click", (e) => {
  e.preventDefault();
  logout();
});

// ---------- State ----------
const callManager = new CallManager({ myUsername });
let myPrivateKey = null; // CryptoKey, unlocked via password (this session)
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
  await loadGroups();
  await loadInbox();
  renderConvoList();

  // Arrived via a "Join Quick Room" style deep link? Not applicable here -
  // that flow lives in index.html. Nothing to do on this page for it.
}

function connectSocket() {
  socket = io(SERVER_URL || undefined, { auth: { token } });
  callManager.attach(socket);

  socket.on("new-message", async (m) => {
    await ingestMessage(m);
    renderConvoList();
    const key = threadKeyFor(m);
    if (activeThreadKey === key) {
      renderThread(key);
      markThreadAsRead(key);
    }
  });

  socket.on("message-deleted", ({ id }) => {
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

async function decryptMessage(m) {
  const blob = m.recipientBlob;
  const plaintext = await decryptFromPublicKey(myPrivateKey, blob.ephemeralPublicKey, blob.iv, blob.ciphertext);
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
    const decrypted = await decryptMessage(raw);
    const key = threadKeyFor(raw);

    if (!threads.has(key)) {
      if (raw.groupId) {
        threads.set(key, { type: "group", groupId: raw.groupId, name: "Group", members: null, messages: [] });
      } else {
        const peer = decrypted.mine ? raw.recipientUsername : raw.senderUsername;
        threads.set(key, { type: "dm", peerUsername: peer, peerPublicKey: null, messages: [] });
      }
    }
    const thread = threads.get(key);
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
    case "room-invite": return "Quick Room invite";
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
    const label = isGroup ? thread.name : `@${thread.peerUsername}`;
    const initials = isGroup ? ICONS.users : thread.peerUsername.slice(0, 2).toUpperCase();
    const senderPrefix = isGroup && last && !last.mine ? `${last.senderUsername}: ` : "";
    const online = !isGroup && onlineUsernames.has(thread.peerUsername);
    const div = document.createElement("div");
    div.className = "convo-item";
    div.innerHTML = `
      <div class="avatar">${initials}${isGroup ? "" : `<span class="presence-dot ${online ? "online" : ""}"></span>`}</div>
      <div class="convo-meta">
        <div class="convo-username">${escapeHtml(label)}</div>
        <div class="convo-preview">${escapeHtml(senderPrefix + (last ? previewFor(last.envelope) : "No messages yet"))}</div>
      </div>
      <div class="convo-time">${last ? formatTime(last.createdAt) : ""}</div>
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
      div.innerHTML = `<div class="avatar">${u.username.slice(0, 2).toUpperCase()}</div><div class="convo-username">@${u.username}</div>`;
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
        div.innerHTML = `<div class="avatar">${u.username.slice(0, 2).toUpperCase()}</div><div class="convo-username">@${u.username}</div>`;
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
    chip.innerHTML = `@${username} <button data-u="${username}">×</button>`;
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

  $("threadPeerName").textContent = thread.type === "group" ? thread.name : `@${thread.peerUsername}`;
  $("convoListView").classList.add("hidden");
  $("threadView").classList.remove("hidden");
  $("typingIndicator").classList.add("hidden");
  updateThreadHeaderStatus(key);
  renderThread(key);
  markThreadAsRead(key);
  $("threadInput").focus();
}

$("backBtn").onclick = () => {
  activeThreadKey = null;
  $("threadView").classList.add("hidden");
  $("convoListView").classList.remove("hidden");
  renderConvoList();
};

function updateThreadHeaderStatus(key) {
  const thread = threads.get(key);
  if (!thread) return;
  if (thread.type === "dm") {
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
  const label = thread?.type === "group" ? `@${fromUsername} is typing…` : "Typing…";
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
  if (!thread) return;
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

  if (showSender && !m.mine) {
    const sender = document.createElement("div");
    sender.className = "msg-sender";
    sender.textContent = `@${m.senderUsername}`;
    div.appendChild(sender);
  }

  div.appendChild(renderEnvelopeContent(m.envelope));

  const time = document.createElement("div");
  time.className = "msg-time";
  time.textContent = formatTime(m.createdAt);
  if (m.mine) time.appendChild(renderTicks(m.deliveryStatus));
  div.appendChild(time);

  const delBtn = document.createElement("button");
  delBtn.className = "msg-delete-btn";
  delBtn.title = "Delete";
  delBtn.innerHTML = ICONS.trash;
  delBtn.onclick = (e) => { e.stopPropagation(); showDeleteMenu(e.currentTarget, m); };
  div.appendChild(delBtn);

  return div;
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
    wrap.innerHTML = `
      <div class="room-invite-label">${ICONS.room}<span>Quick Room invite</span></div>
      <button class="join-room-btn primary">Join Quick Room</button>
    `;
    wrap.querySelector(".join-room-btn").onclick = () => {
      window.location.href = `index.html?room=${encodeURIComponent(envelope.roomCode)}`;
    };
    return wrap;
  }

  if (envelope.type === "file") {
    wrap.className = "msg-text";
    const blob = base64ToBlob(envelope.dataBase64, envelope.mimeType);
    const url = URL.createObjectURL(blob);
    if (envelope.mimeType?.startsWith("image/")) {
      const img = document.createElement("img");
      img.src = url;
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
      wrap.appendChild(a);
    }
    return wrap;
  }

  wrap.className = "msg-text";
  wrap.textContent = "[Unsupported message]";
  return wrap;
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

function showDeleteMenu(anchor, m) {
  document.querySelectorAll(".delete-menu").forEach((el) => el.remove());
  const menu = document.createElement("div");
  menu.className = "delete-menu";
  menu.innerHTML = `<button data-scope="me">Delete for me</button><button data-scope="everyone" class="danger">Delete for everyone</button>`;
  document.body.appendChild(menu);
  const rect = anchor.getBoundingClientRect();
  menu.style.top = `${rect.bottom + window.scrollY + 4}px`;
  menu.style.left = `${Math.min(rect.left + window.scrollX, window.innerWidth - 180)}px`;

  menu.querySelectorAll("button").forEach((btn) => {
    btn.onclick = async () => {
      menu.remove();
      try {
        await authedFetch(`/api/messages/${m.id}`, { method: "DELETE", body: JSON.stringify({ scope: btn.dataset.scope }) });
        const thread = threads.get(activeThreadKey);
        const idx = thread.messages.findIndex((x) => x.id === m.id);
        if (idx !== -1) thread.messages.splice(idx, 1);
        renderThread(activeThreadKey);
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

// ---------- Sending ----------
async function sendEnvelope(envelope) {
  const thread = threads.get(activeThreadKey);
  if (!thread) return;

  try {
    let body;
    if (thread.type === "group") {
      const members = await ensureGroupMembers(thread.groupId);
      const recipients = [];
      for (const member of members) {
        const enc = await encryptToPublicKey(member.publicKey, JSON.stringify(envelope));
        recipients.push({ username: member.username, ...enc });
      }
      body = { groupId: thread.groupId, recipients };
    } else {
      const forRecipient = await encryptToPublicKey(thread.peerPublicKey, JSON.stringify(envelope));
      const forSender = await encryptToPublicKey(myPublicKey, JSON.stringify(envelope));
      body = {
        recipientUsername: thread.peerUsername,
        recipients: [
          { username: thread.peerUsername, ...forRecipient },
          { username: myUsername, ...forSender },
        ],
      };
    }

    const res = await authedFetch("/api/messages/send", { method: "POST", body: JSON.stringify(body) });
    await ingestMessage(res.message);
    renderThread(activeThreadKey);
    renderConvoList();
  } catch (err) {
    alert(err.message);
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

// ---------- Video call (rings the person / group you're chatting with) ----------
$("threadVideoCallBtn").onclick = async () => {
  const thread = threads.get(activeThreadKey);
  if (!thread) return;
  if (thread.type === "group") {
    const members = await ensureGroupMembers(thread.groupId);
    const targets = members.map((m) => m.username).filter((u) => u !== myUsername);
    callManager.startCall({ targets, title: thread.name, groupName: thread.name });
  } else {
    callManager.startCall({ targets: [thread.peerUsername], title: `@${thread.peerUsername}` });
  }
};

// ---------- Share Quick Room ----------
function generateRoomCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

$("msgShareRoomBtn").onclick = async () => {
  const code = generateRoomCode();
  await sendEnvelope({ type: "room-invite", roomCode: code });
  window.location.href = `index.html?room=${encodeURIComponent(code)}`;
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
