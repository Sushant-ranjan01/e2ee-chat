import * as C from "./crypto.js";
import { PeerLink } from "./webrtc.js";
import { SERVER_URL } from "./config.js";

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
const screens = { landing: $("landing"), waiting: $("waiting"), chat: $("chat") };
function showScreen(name) {
  Object.values(screens).forEach((s) => s.classList.add("hidden"));
  screens[name].classList.remove("hidden");
}

// ---------- State ----------
let socket;
let roomId = null;
let isInitiator = false;
let keyPair = null;
let myPublicKeyB64 = null;
let peerPublicKeyB64 = null;
let sharedKey = null;
let peerLink = null;
let localStream = null;
const CHUNK_SIZE = 16 * 1024; // 16KB plaintext per chunk
const incomingFiles = new Map(); // id -> { meta, chunks: [], received }

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

  socket.on("joined", async ({ isInitiator: initiator }) => {
    isInitiator = initiator;
    $("roomCodeDisplay").textContent = roomId;
    $("headerRoomCode").textContent = roomId;
    showScreen("waiting");
  });

  socket.on("peer-ready", async () => {
    // Both participants present. Exchange public keys, then establish WebRTC.
    peerLink = new PeerLink(socket, roomId, isInitiator);
    wirePeerLink();

    socket.emit("signal", { kind: "pubkey", key: myPublicKeyB64 });

    if (isInitiator) {
      await peerLink.createOffer();
    }
  });

  socket.on("signal", async (payload) => {
    if (payload.kind === "pubkey") {
      peerPublicKeyB64 = payload.key;
      const peerPublicKey = await C.importPublicKey(peerPublicKeyB64);
      sharedKey = await C.deriveSharedKey(keyPair.privateKey, peerPublicKey);
      await showFingerprint();
    } else {
      await peerLink.handleSignal(payload);
    }
  });

  socket.on("peer-left", () => {
    addSystemMessage("The other person left the chat.");
    $("statusDot").classList.remove("connected");
    $("headerStatus").textContent = "peer disconnected";
  });
}

function wirePeerLink() {
  peerLink.onDataChannelOpen = () => {
    if (sharedKey) enterChat();
  };
  peerLink.onDataChannelMessage = handleIncoming;
  peerLink.onConnectionStateChange = (state) => {
    if (state === "connected") {
      $("statusDot").classList.add("connected");
      $("headerStatus").textContent = "connected · end-to-end encrypted";
    } else if (state === "disconnected" || state === "failed" || state === "closed") {
      $("statusDot").classList.remove("connected");
      $("headerStatus").textContent = state;
    }
  };
  peerLink.onRemoteTrack = (stream) => {
    $("remoteVideo").srcObject = stream;
    $("videoArea").classList.remove("hidden");
    $("endCallBtn").classList.remove("hidden");
  };
}

async function showFingerprint() {
  // A short verification code derived from BOTH public keys, sorted so both
  // sides compute the identical string. If this doesn't match what your
  // contact sees, someone is intercepting the key exchange (MITM) - don't trust the chat.
  const combined = [myPublicKeyB64, peerPublicKeyB64].sort().join("|");
  const hash = await C.sha256Hex(combined);
  const code = hash.slice(0, 12).match(/.{1,4}/g).join(" ").toUpperCase();
  $("fingerprintCode").textContent = code;
  $("fingerprintBar").classList.remove("hidden");
  if (peerLink && peerLink.dataChannel && peerLink.dataChannel.readyState === "open") {
    enterChat();
  }
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
  if (!text || !sharedKey) return;
  const { iv, data } = await C.encrypt(sharedKey, text);
  const envelope = { type: "text", iv, data };
  if (peerLink.send(JSON.stringify(envelope))) {
    addBubble("me", { kind: "text", text });
    $("textInput").value = "";
  }
}

// ---------- Emoji picker ----------
const EMOJIS = "😀😁😂🤣😊😍😘😜🤔😎😢😭😡🥳😴🤯👍👎👏🙏🔥❤️💯🎉🎂🍕🍔🍺☕🌈☀️🌙⭐🚀✈️🏆⚽🎮📷🎵🎬💡🔒✅❌❓❗".match(/./gu);
const picker = $("emojiPicker");
EMOJIS.forEach((e) => {
  const span = document.createElement("span");
  span.textContent = e;
  span.onclick = () => {
    $("textInput").value += e;
    $("textInput").focus();
  };
  picker.appendChild(span);
});
$("emojiBtn").onclick = () => picker.classList.toggle("hidden");

// ---------- Sending: files (also used for recorded audio/video) ----------
$("fileBtn").onclick = () => $("fileInput").click();
$("fileInput").onchange = async (e) => {
  for (const file of e.target.files) {
    await sendFile(file);
  }
  $("fileInput").value = "";
};

async function sendFile(file) {
  if (!sharedKey) return;
  const id = crypto.randomUUID();
  const buf = await file.arrayBuffer();
  const totalChunks = Math.ceil(buf.byteLength / CHUNK_SIZE) || 1;

  const metaPlain = JSON.stringify({
    name: file.name,
    mime: file.type || "application/octet-stream",
    size: buf.byteLength,
    totalChunks,
  });
  const metaEnc = await C.encrypt(sharedKey, metaPlain);
  peerLink.send(JSON.stringify({ type: "file-meta", id, iv: metaEnc.iv, data: metaEnc.data }));

  const bubbleId = addBubble("me", { kind: "file-outgoing", name: file.name, mime: file.type, size: buf.byteLength });

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const chunk = buf.slice(start, start + CHUNK_SIZE);
    const enc = await C.encrypt(sharedKey, chunk);
    await peerLink.waitForBufferedAmountLow();
    peerLink.send(JSON.stringify({ type: "file-chunk", id, index: i, total: totalChunks, iv: enc.iv, data: enc.data }));
    updateProgress(bubbleId, Math.round(((i + 1) / totalChunks) * 100));
  }

  // Also show local preview using the original (unencrypted, since it's ours) blob
  finalizeOutgoingPreview(bubbleId, file);
}

// ---------- Receiving ----------
async function handleIncoming(raw) {
  let envelope;
  try {
    envelope = JSON.parse(raw);
  } catch {
    return;
  }

  if (envelope.type === "text") {
    const text = await C.decryptToText(sharedKey, envelope.iv, envelope.data);
    addBubble("them", { kind: "text", text });
    return;
  }

  if (envelope.type === "file-meta") {
    const plain = await C.decryptToText(sharedKey, envelope.iv, envelope.data);
    const meta = JSON.parse(plain);
    const bubbleId = addBubble("them", {
      kind: "file-incoming",
      name: meta.name,
      mime: meta.mime,
      size: meta.size,
    });
    incomingFiles.set(envelope.id, { meta, chunks: new Array(meta.totalChunks), received: 0, bubbleId });
    return;
  }

  if (envelope.type === "file-chunk") {
    const entry = incomingFiles.get(envelope.id);
    if (!entry) return;
    const buf = await C.decrypt(sharedKey, envelope.iv, envelope.data);
    entry.chunks[envelope.index] = buf;
    entry.received++;
    updateProgress(entry.bubbleId, Math.round((entry.received / entry.meta.totalChunks) * 100));

    if (entry.received === entry.meta.totalChunks) {
      const blob = new Blob(entry.chunks, { type: entry.meta.mime });
      finalizeIncomingPreview(entry.bubbleId, blob, entry.meta);
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

  if (content.kind === "text") {
    div.textContent = content.text;
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
    a.textContent = `📄 Download ${name}`;
    el.appendChild(a);
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

// ---------- Voice message recording ----------
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
    await peerLink.addLocalStream(localStream);
  } catch (err) {
    addSystemMessage("Couldn't start call: " + err.message);
  }
};

$("endCallBtn").onclick = () => {
  localStream?.getTracks().forEach((t) => t.stop());
  $("videoArea").classList.add("hidden");
  $("endCallBtn").classList.add("hidden");
  $("localVideo").srcObject = null;
};

// ---------- Leave ----------
$("leaveBtn").onclick = () => {
  peerLink?.close();
  socket?.emit("leave-room");
  socket?.disconnect();
  location.reload();
};

$("copyCodeBtn").onclick = () => {
  navigator.clipboard.writeText(roomId);
  $("copyCodeBtn").textContent = "Copied!";
  setTimeout(() => ($("copyCodeBtn").textContent = "Copy code"), 1500);
};
