import * as C from "./crypto.js";
import { PeerLink } from "./webrtc.js";
import { SERVER_URL } from "./config.js";
import { ICONS } from "./icons.js";

const $ = (id) => document.getElementById(id);

// ---------- Auth gate ----------
// This app requires an account (see login.html) before it does anything.
const sessionToken = localStorage.getItem("e2ee_token");
const myUsername = localStorage.getItem("e2ee_username");
if (!sessionToken) {
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

const loggedInPhoneEl = $("loggedInPhone");
if (loggedInPhoneEl) loggedInPhoneEl.textContent = myUsername ? `@${myUsername}` : "";
$("landingLogout")?.addEventListener("click", (e) => {
  e.preventDefault();
  logout();
});
$("logoutBtn")?.addEventListener("click", logout);

// ---------- Screens ----------
const screens = { landing: $("landing"), chat: $("chat") };
function showScreen(name) {
  Object.values(screens).forEach((s) => s.classList.add("hidden"));
  screens[name].classList.remove("hidden");
}

// ---------- State ----------
// A Quick Room can now hold multiple people. Every other participant gets
// their own PeerLink (own direct WebRTC connection) and their own pairwise
// AES key — see the module doc comment in webrtc.js for why.
let socket;
let roomId = null;
let roomMaxSize = 6;
let keyPair = null; // ONE keypair per room session, reused for every pairwise ECDH exchange
let myPublicKeyB64 = null;
let localStream = null;
const CHUNK_SIZE = 16 * 1024; // 16KB plaintext per chunk

/** socketId -> { peerLink, username, publicKeyB64, sharedKey, videoEl } */
const peers = new Map();
/** file transfer id -> { meta, chunks, received, bubbleId, fromSocketId } */
const incomingFiles = new Map();

// ---------- Landing ----------
$("createBtn").onclick = () => {
  const code = generateRoomCode();
  startRoom(code);
};
$("joinBtn").onclick = () => {
  const code = $("joinCode").value.trim().toUpperCase();
  if (!code) return;
  startRoom(code);
};
$("joinCode").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("joinBtn").click();
});

// Arrived via a "Join Quick Room" invite link from Messages
// (index.html?room=CODE)? Auto-join it straight away.
const inviteRoomCode = new URLSearchParams(window.location.search).get("room");
if (inviteRoomCode) {
  // Consume the ?room= param right away. Otherwise any reload (or the old
  // "leave" button, which reloaded the page) would instantly re-join the
  // same room - which is what made it impossible to get out of a Quick Room.
  history.replaceState(null, "", window.location.pathname);
  startRoom(inviteRoomCode.trim().toUpperCase());
}

function generateRoomCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

async function startRoom(code) {
  $("landingError").textContent = "";
  roomId = code;
  keyPair = await C.generateKeyPair();
  myPublicKeyB64 = await C.exportPublicKey(keyPair.publicKey);

  socket = io(SERVER_URL || undefined, { auth: { token: sessionToken } });
  socket.on("connect", () => socket.emit("join-room", roomId));

  socket.on("connect_error", (err) => {
    if (err.message === "unauthorized") {
      logout(); // session invalid/expired - send back to login
    } else {
      $("landingError").textContent = "Connection error: " + err.message;
    }
  });

  socket.on("room-error", (msg) => {
    $("landingError").textContent = msg;
    showScreen("landing");
    socket.disconnect();
  });

  socket.on("joined", async ({ existingPeers, maxSize }) => {
    roomMaxSize = maxSize;
    $("headerRoomCode").textContent = roomId;
    enterChat();
    addSystemMessage(
      existingPeers.length === 0
        ? `Room ${roomId} created. Share the code to invite others (up to ${maxSize} people).`
        : `Joined room ${roomId}.`
    );
    updateHeaderStatus();

    // We joined after these people - we initiate the connection to each.
    for (const peer of existingPeers) {
      await connectToPeer(peer.socketId, peer.username, true);
    }
  });

  socket.on("peer-joined", async ({ socketId, username }) => {
    addSystemMessage(`${username} joined the room.`);
    // They joined after us - they'll send the offer; we just get ready.
    await connectToPeer(socketId, username, false);
  });

  socket.on("signal", async (payload) => {
    if (payload.kind === "pubkey") {
      const entry = peers.get(payload.from);
      if (!entry) return;
      entry.publicKeyB64 = payload.key;
      const peerPublicKey = await C.importPublicKey(payload.key);
      entry.sharedKey = await C.deriveSharedKey(keyPair.privateKey, peerPublicKey);
      await addFingerprintFor(entry);
    } else {
      const entry = peers.get(payload.from);
      if (entry) await entry.peerLink.handleSignal(payload);
    }
  });

  socket.on("peer-left", ({ socketId }) => {
    const entry = peers.get(socketId);
    if (!entry) return;
    addSystemMessage(`${entry.username} left the room.`);
    entry.peerLink.close();
    entry.videoEl?.remove();
    removeFingerprintFor(socketId);
    peers.delete(socketId);
    updateHeaderStatus();
    if (peers.size === 0) $("videoArea").classList.add("hidden");
  });
}

async function connectToPeer(remoteSocketId, remoteUsername, isInitiator) {
  const peerLink = new PeerLink(socket, remoteSocketId, remoteUsername, isInitiator);
  const entry = { peerLink, username: remoteUsername, publicKeyB64: null, sharedKey: null, videoEl: null };
  peers.set(remoteSocketId, entry);

  peerLink.onDataChannelOpen = () => updateHeaderStatus();
  peerLink.onDataChannelMessage = (raw) => handleIncoming(raw, remoteSocketId);
  peerLink.onConnectionStateChange = (state) => {
    updateHeaderStatus();
    if (state === "failed" || state === "closed") {
      // Leave cleanup is normally driven by the server's peer-left event;
      // this just keeps the UI honest if a connection dies without one.
      updateHeaderStatus();
    }
  };
  peerLink.onRemoteTrack = (stream) => {
    let videoEl = entry.videoEl;
    if (!videoEl) {
      videoEl = document.createElement("video");
      videoEl.autoplay = true;
      videoEl.playsInline = true;
      entry.videoEl = videoEl;
      $("videoArea").appendChild(videoEl);
      $("videoArea").classList.remove("hidden");
      $("endCallBtn").classList.remove("hidden");
    }
    videoEl.srcObject = stream;
  };

  // Send our public key to this specific peer - each pairwise connection
  // gets its own AES key, derived independently the moment their key arrives.
  socket.emit("signal", { to: remoteSocketId, kind: "pubkey", key: myPublicKeyB64 });

  if (isInitiator) {
    await peerLink.createOffer();
  }
}

function updateHeaderStatus() {
  const connectedCount = [...peers.values()].filter(
    (p) => p.peerLink.dataChannel?.readyState === "open"
  ).length;
  $("statusDot").classList.toggle("connected", connectedCount > 0);
  $("headerStatus").textContent =
    connectedCount === 0
      ? "waiting for others to join…"
      : `${connectedCount} ${connectedCount === 1 ? "person" : "people"} connected · end-to-end encrypted`;
}

// ---------- Per-peer fingerprint verification ----------
async function addFingerprintFor(entry) {
  // A short verification code derived from BOTH public keys in this pair,
  // sorted so both sides compute the identical string. If what you see for
  // someone doesn't match what THEY see for you, someone is intercepting
  // that specific connection (MITM) - don't trust messages to/from them.
  const combined = [myPublicKeyB64, entry.publicKeyB64].sort().join("|");
  const hash = await C.sha256Hex(combined);
  const code = hash.slice(0, 12).match(/.{1,4}/g).join(" ").toUpperCase();

  let row = document.getElementById(`fp-${entry.username}`);
  if (!row) {
    row = document.createElement("div");
    row.id = `fp-${entry.username}`;
    row.className = "fingerprint-row";
    $("fingerprintList").appendChild(row);
  }
  row.textContent = `${entry.username}: ${code}`;
  $("fingerprintBar").classList.remove("hidden");
}

function removeFingerprintFor(socketId) {
  const entry = peers.get(socketId);
  if (!entry) return;
  document.getElementById(`fp-${entry.username}`)?.remove();
}

function enterChat() {
  showScreen("chat");
  $("textInput").focus();
}

// ---------- Sending: text ----------
$("sendBtn").onclick = sendTextMessage;
$("textInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendTextMessage();
});

async function sendTextMessage() {
  const text = $("textInput").value.trim();
  if (!text) return;
  const envelope = { type: "text" };
  for (const entry of peers.values()) {
    if (!entry.sharedKey) continue;
    const { iv, data } = await C.encrypt(entry.sharedKey, text);
    entry.peerLink.send(JSON.stringify({ ...envelope, iv, data }));
  }
  addBubble("me", { kind: "text", text });
  $("textInput").value = "";
}

// ---------- Sending: files (also used for recorded audio/video) ----------
$("fileBtn").onclick = () => $("fileInput").click();
$("fileInput").onchange = async (e) => {
  for (const file of e.target.files) {
    await sendFile(file);
  }
  $("fileInput").value = "";
};

async function sendFile(file) {
  if (peers.size === 0) return;
  const id = crypto.randomUUID();
  const buf = await file.arrayBuffer();
  const totalChunks = Math.ceil(buf.byteLength / CHUNK_SIZE) || 1;
  const metaPlain = JSON.stringify({
    name: file.name,
    mime: file.type || "application/octet-stream",
    size: buf.byteLength,
    totalChunks,
  });

  const bubbleId = addBubble("me", { kind: "file-outgoing", name: file.name, mime: file.type, size: buf.byteLength });

  // Send to every currently-connected peer. Each gets its own encrypted
  // copy (their own pairwise key) - the plaintext bytes are the same, the
  // ciphertext isn't.
  for (const entry of peers.values()) {
    if (!entry.sharedKey) continue;
    const metaEnc = await C.encrypt(entry.sharedKey, metaPlain);
    entry.peerLink.send(JSON.stringify({ type: "file-meta", id, iv: metaEnc.iv, data: metaEnc.data }));

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const chunk = buf.slice(start, start + CHUNK_SIZE);
      const enc = await C.encrypt(entry.sharedKey, chunk);
      await entry.peerLink.waitForBufferedAmountLow();
      entry.peerLink.send(
        JSON.stringify({ type: "file-chunk", id, index: i, total: totalChunks, iv: enc.iv, data: enc.data })
      );
    }
  }

  updateProgress(bubbleId, 100);
  finalizeOutgoingPreview(bubbleId, file);
}

// ---------- Receiving ----------
async function handleIncoming(raw, fromSocketId) {
  const entry = peers.get(fromSocketId);
  if (!entry || !entry.sharedKey) return;

  let envelope;
  try {
    envelope = JSON.parse(raw);
  } catch {
    return;
  }

  const showSender = peers.size > 1; // label bubbles once it's more than a 1:1 chat

  if (envelope.type === "text") {
    const text = await C.decryptToText(entry.sharedKey, envelope.iv, envelope.data);
    addBubble("them", { kind: "text", text, sender: showSender ? entry.username : null });
    return;
  }

  if (envelope.type === "file-meta") {
    const plain = await C.decryptToText(entry.sharedKey, envelope.iv, envelope.data);
    const meta = JSON.parse(plain);
    const bubbleId = addBubble("them", {
      kind: "file-incoming",
      name: meta.name,
      mime: meta.mime,
      size: meta.size,
      sender: showSender ? entry.username : null,
    });
    incomingFiles.set(envelope.id, { meta, chunks: new Array(meta.totalChunks), received: 0, bubbleId, fromSocketId });
    return;
  }

  if (envelope.type === "file-chunk") {
    const fileEntry = incomingFiles.get(envelope.id);
    if (!fileEntry || fileEntry.fromSocketId !== fromSocketId) return;
    const buf = await C.decrypt(entry.sharedKey, envelope.iv, envelope.data);
    fileEntry.chunks[envelope.index] = buf;
    fileEntry.received++;
    updateProgress(fileEntry.bubbleId, Math.round((fileEntry.received / fileEntry.meta.totalChunks) * 100));

    if (fileEntry.received === fileEntry.meta.totalChunks) {
      const blob = new Blob(fileEntry.chunks, { type: fileEntry.meta.mime });
      finalizeIncomingPreview(fileEntry.bubbleId, blob, fileEntry.meta);
      incomingFiles.delete(envelope.id);
    }
    return;
  }
}

// ---------- Bubble rendering ----------
let bubbleCounter = 0;
function addBubble(who, content) {
  const id = `bubble-${++bubbleCounter}`;
  const div = document.createElement("div");
  div.className = `bubble ${who}`;
  div.id = id;

  if (content.sender) {
    const sender = document.createElement("div");
    sender.className = "msg-sender";
    sender.textContent = `@${content.sender}`;
    div.appendChild(sender);
  }

  if (content.kind === "text") {
    const text = document.createElement("div");
    text.textContent = content.text;
    div.appendChild(text);
  } else if (content.kind === "file-outgoing" || content.kind === "file-incoming") {
    const label = document.createElement("div");
    label.textContent = `${who === "me" ? "Sending" : "Receiving"}: ${content.name}`;
    div.appendChild(label);
    const progress = document.createElement("div");
    progress.className = "progress";
    const fill = document.createElement("div");
    fill.className = "progress-fill";
    progress.appendChild(fill);
    div.appendChild(progress);
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = formatBytes(content.size);
    div.appendChild(meta);
  }

  $("messages").appendChild(div);
  $("messages").scrollTop = $("messages").scrollHeight;
  return id;
}

function addSystemMessage(text) {
  const div = document.createElement("div");
  div.className = "bubble system";
  div.textContent = text;
  $("messages").appendChild(div);
  $("messages").scrollTop = $("messages").scrollHeight;
}

function updateProgress(bubbleId, pct) {
  const el = document.getElementById(bubbleId);
  if (!el) return;
  const fill = el.querySelector(".progress-fill");
  if (fill) fill.style.width = pct + "%";
}

function finalizeOutgoingPreview(bubbleId, file) {
  const url = URL.createObjectURL(file);
  renderMediaInto(bubbleId, url, file.type, file.name);
}

function finalizeIncomingPreview(bubbleId, blob, meta) {
  const url = URL.createObjectURL(blob);
  renderMediaInto(bubbleId, url, meta.mime, meta.name);
}

function renderMediaInto(bubbleId, url, mime, name) {
  const el = document.getElementById(bubbleId);
  if (!el) return;
  const progress = el.querySelector(".progress");
  if (progress) progress.remove();

  if (mime.startsWith("image/")) {
    const img = document.createElement("img");
    img.src = url;
    el.appendChild(img);
  } else if (mime.startsWith("video/")) {
    const video = document.createElement("video");
    video.src = url;
    video.controls = true;
    el.appendChild(video);
  } else if (mime.startsWith("audio/")) {
    const audio = document.createElement("audio");
    audio.src = url;
    audio.controls = true;
    el.appendChild(audio);
  } else {
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.className = "file-link";
    a.innerHTML = `${ICONS.file}<span>Download ${escapeHtml(name)}</span>`;
    el.appendChild(a);
  }
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

// ---------- Voice/video message recording ----------
let mediaRecorder = null;
let recordedChunks = [];
let recordingKind = null; // 'audio' | 'video'
let recordingStreamToStop = null;

$("audioBtn").onclick = () => startRecording("audio");
$("videoMsgBtn").onclick = () => startRecording("video");
$("cancelRecordBtn").onclick = () => stopRecording(false);
$("stopRecordBtn").onclick = () => stopRecording(true);

async function startRecording(kind) {
  try {
    const constraints = kind === "video" ? { audio: true, video: true } : { audio: true };
    const stream = await navigator.mediaDevices.getUserMedia(constraints);
    recordingStreamToStop = stream;
    recordingKind = kind;
    recordedChunks = [];
    mediaRecorder = new MediaRecorder(stream);
    mediaRecorder.ondataavailable = (e) => {
      if (e.data.size > 0) recordedChunks.push(e.data);
    };
    mediaRecorder.start();
    $("recordingBar").classList.remove("hidden");
    $("recordingLabel").textContent = kind === "video" ? "Recording video…" : "Recording voice…";
  } catch (err) {
    addSystemMessage("Couldn't access microphone/camera: " + err.message);
  }
}

function stopRecording(send) {
  if (!mediaRecorder) return;
  mediaRecorder.onstop = async () => {
    recordingStreamToStop?.getTracks().forEach((t) => t.stop());
    $("recordingBar").classList.add("hidden");
    if (send && recordedChunks.length) {
      const mime = recordingKind === "video" ? "video/webm" : "audio/webm";
      const blob = new Blob(recordedChunks, { type: mime });
      const file = new File([blob], `${recordingKind}-message-${Date.now()}.webm`, { type: mime });
      await sendFile(file);
    }
    mediaRecorder = null;
  };
  mediaRecorder.stop();
}

// ---------- Live call ----------
$("callBtn").onclick = async () => {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    $("localVideo").srcObject = localStream;
    $("videoArea").classList.remove("hidden");
    $("endCallBtn").classList.remove("hidden");
    for (const entry of peers.values()) {
      await entry.peerLink.addLocalStream(localStream);
    }
  } catch (err) {
    addSystemMessage("Couldn't start call: " + err.message);
  }
};

$("endCallBtn").onclick = () => {
  localStream?.getTracks().forEach((t) => t.stop());
  localStream = null;
  $("localVideo").srcObject = null;
  const anyRemoteVideo = [...peers.values()].some((p) => p.videoEl);
  if (!anyRemoteVideo) $("videoArea").classList.add("hidden");
  $("endCallBtn").classList.add("hidden");
};

// ---------- Leave ----------
$("leaveBtn").onclick = () => {
  for (const entry of peers.values()) entry.peerLink.close();
  peers.clear();
  socket?.emit("leave-room");
  socket?.disconnect();
  localStream?.getTracks().forEach((t) => t.stop());
  window.location.href = "messages.html";
};

// Also leave cleanly when using the header's Messages link or the Android
// hardware back button (otherwise the room stays "occupied" until timeout).
function leaveRoomQuietly() {
  for (const entry of peers.values()) entry.peerLink.close();
  peers.clear();
  socket?.emit("leave-room");
  socket?.disconnect();
  localStream?.getTracks().forEach((t) => t.stop());
}
$("chatMessagesLink")?.addEventListener("click", leaveRoomQuietly);
window.addEventListener("pagehide", leaveRoomQuietly);

$("copyCodeBtn")?.addEventListener("click", () => {
  navigator.clipboard.writeText(roomId);
  $("copyCodeBtn").title = "Copied!";
  setTimeout(() => ($("copyCodeBtn").title = "Copy room code"), 1500);
});
