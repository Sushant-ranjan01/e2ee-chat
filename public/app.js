import * as C from "./crypto.js";
import { PeerLink } from "./webrtc.js";
import { SERVER_URL } from "./config.js";
import { ICONS } from "./icons.js";
import { attachMenu, closeMenus } from "./menu.js";
import { initAppLock } from "./applock.js";
import { setBackHandler, isNative, reportAppState, unregisterPush, initNotifications, notify, onNotificationTap } from "./native.js";

const $ = (id) => document.getElementById(id);

// ---------- Auth gate ----------
// This app requires an account (see login.html) before it does anything.
const sessionToken = localStorage.getItem("e2ee_token");
const myUsername = localStorage.getItem("e2ee_username");
if (!sessionToken) {
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

const loggedInPhoneEl = $("loggedInPhone");
if (loggedInPhoneEl) loggedInPhoneEl.textContent = myUsername || "";
initAppLock(); // PIN lock screen (no-op unless the person turned it on)

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
let hasJoined = false;       // have we been inside this room at least once?
let shareShownOnce = false;  // auto-open the share panel only the first time
const CHUNK_SIZE = 16 * 1024; // 16KB plaintext per chunk

/** socketId -> { peerLink, username, publicKeyB64, sharedKey, videoEl } */
const peers = new Map();
/** file transfer id -> { meta, chunks, received, bubbleId, fromSocketId } */
const incomingFiles = new Map();

// ---------- Landing ----------
$("createBtn").onclick = () => {
  const code = generateRoomCode();
  startRoom(code, { create: true });
};
$("joinBtn").onclick = () => {
  const code = $("joinCode").value.trim().toUpperCase();
  if (!code) return;
  startRoom(code); // joining never creates: the room must already exist
};
$("joinCode").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("joinBtn").click();
});

// Arrived via a "Join Quick Room" invite link from Messages
// (index.html?room=CODE)? Auto-join it straight away.
const urlParams = new URLSearchParams(window.location.search);
const inviteRoomCode = urlParams.get("room");
// ?call=video  -> start the camera/mic automatically once we're in the room
//                 (direct video call from a chat thread).
// ?from=messages -> where "Leave" should take us back to.
const autoStartCall = urlParams.get("call") === "video";
const cameFromMessages = urlParams.get("from") === "messages";
// ?create=1 -> this link was opened by the person who STARTED the room (a new
// room from Messages, or the caller of a video call). Everyone else only joins
// rooms that already exist.
const inviteCreate = urlParams.get("create") === "1";
if (inviteRoomCode) {
  startRoom(inviteRoomCode.trim().toUpperCase(), { create: inviteCreate });
}

function generateRoomCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

async function startRoom(code, { create = false } = {}) {
  $("landingError").textContent = "";
  roomId = code;
  keyPair = await C.generateKeyPair();
  myPublicKeyB64 = await C.exportPublicKey(keyPair.publicKey);

  socket = io(SERVER_URL || undefined, { auth: { token: sessionToken } });
  reportAppState(socket); // lets the server know when to use push instead of the live socket

  socket.on("connect", () => {
    if (hasJoined) {
      // The connection dropped and came back (phone slept, network switched...).
      // The server removed us from the room meanwhile, so start clean and rejoin.
      // If the room has been empty for 2 minutes it will be gone, and we'll be told.
      resetPeers();
      addSystemMessage("Reconnected - rejoining the room…");
    }
    socket.emit("join-room", { roomId, create: hasJoined ? false : create });
  });

  socket.on("disconnect", () => {
    if (!hasJoined) return;
    $("statusDot").classList.remove("connected");
    $("headerStatus").textContent = "connection lost - reconnecting…";
  });

  socket.on("connect_error", (err) => {
    if (err.message === "unauthorized") {
      logout(); // session invalid/expired - send back to login
    } else {
      $("landingError").textContent = "Connection error: " + err.message;
    }
  });

  socket.on("room-error", (msg) => {
    // The room is gone (expired) or full. If we were inside, erase everything
    // this device still holds about it.
    wipeRoomState();
    $("landingError").textContent = msg;
    showScreen("landing");
    socket.disconnect();
  });

  socket.on("joined", async ({ existingPeers, maxSize, createdByMe, emptyTtlSeconds }) => {
    const firstTime = !hasJoined;
    hasJoined = true;
    roomMaxSize = maxSize;
    if (emptyTtlSeconds) $("shareTtl").textContent = formatDuration(emptyTtlSeconds);
    $("headerRoomCode").textContent = roomId;
    enterChat();
    if (firstTime) {
      addSystemMessage(
        existingPeers.length === 0
          ? `Room ${roomId} created. It's erased ${formatDuration(emptyTtlSeconds || 120)} after everyone leaves - share it with someone to get started.`
          : `Joined room ${roomId}.`
      );
    }
    updateHeaderStatus();

    // We joined after these people - we initiate the connection to each.
    for (const peer of existingPeers) {
      await connectToPeer(peer.socketId, peer.username, true);
    }

    if (autoStartCall) startCall();

    // Brand-new room made right now: offer to share it straight away.
    if (firstTime && createdByMe && !autoStartCall && !shareShownOnce) {
      shareShownOnce = true;
      openSharePanel();
    }
  });

  // Direct-call extras (rings started from Messages)
  socket.on("call-declined", ({ from }) => addSystemMessage(`${from} declined the call.`));

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
    updateCallUI();
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
    }
    videoEl.srcObject = stream;
    videoEl.play?.().catch(() => {});
    // When the other person ends their call, their tracks are removed -
    // take their (now frozen) tile away.
    stream.onremovetrack = () => {
      if (stream.getTracks().length === 0 && entry.videoEl) {
        entry.videoEl.remove();
        entry.videoEl = null;
        updateCallUI();
      }
    };
    updateCallUI();
  };

  // Send our public key to this specific peer - each pairwise connection
  // gets its own AES key, derived independently the moment their key arrives.
  socket.emit("signal", { to: remoteSocketId, kind: "pubkey", key: myPublicKeyB64 });

  // A call is already running on our side: this newcomer must get our
  // camera/mic too, not just the people who were here when it started.
  // (The offer itself is created automatically - see webrtc.js.)
  if (localStream) peerLink.addLocalStream(localStream);
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
    alertIncoming(entry.username, text.slice(0, 120));
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
    alertIncoming(entry.username, `Sent ${meta.mime?.startsWith("image/") ? "a photo" : meta.mime?.startsWith("audio/") ? "a voice message" : meta.mime?.startsWith("video/") ? "a video" : "a file"}`);
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
    sender.textContent = content.sender;
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

// Every preview URL we create is remembered so it can be revoked when the room
// is wiped (a received file shouldn't linger in memory after the room is gone).
const blobUrls = new Set();
function makeBlobUrl(blob) {
  const url = URL.createObjectURL(blob);
  blobUrls.add(url);
  return url;
}

function finalizeOutgoingPreview(bubbleId, file) {
  const url = makeBlobUrl(file);
  renderMediaInto(bubbleId, url, file.type, file.name);
}

function finalizeIncomingPreview(bubbleId, blob, meta) {
  const url = makeBlobUrl(blob);
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
let micOn = true;
let camOn = true;
let facing = "user"; // "user" = front camera, "environment" = back camera
let wakeLock = null;

function updateCallUI() {
  const inCall = !!localStream;
  const anyRemoteVideo = [...peers.values()].some((p) => p.videoEl);
  $("callBtn").classList.toggle("hidden", inCall);
  $("endCallBtn").classList.toggle("hidden", !inCall);
  $("callControls").classList.toggle("hidden", !inCall);
  $("localVideo").classList.toggle("hidden", !inCall);
  $("localVideo").classList.toggle("mirror", facing === "user");
  $("videoArea").classList.toggle("hidden", !inCall && !anyRemoteVideo);
}

function refreshControlButtons() {
  $("muteBtn").innerHTML = micOn ? ICONS.mic : ICONS.micOff;
  $("muteBtn").classList.toggle("off", !micOn);
  $("muteBtn").title = micOn ? "Mute microphone" : "Unmute microphone";
  $("camToggleBtn").innerHTML = camOn ? ICONS.video : ICONS.videoOff;
  $("camToggleBtn").classList.toggle("off", !camOn);
  $("camToggleBtn").title = camOn ? "Turn camera off" : "Turn camera on";
}

async function startCall() {
  if (localStream) return;
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: { facingMode: facing } });
  } catch (err) {
    addSystemMessage("Couldn't start video call: " + err.message);
    return;
  }
  micOn = true;
  camOn = true;
  refreshControlButtons();
  $("localVideo").srcObject = localStream;
  for (const entry of peers.values()) entry.peerLink.addLocalStream(localStream);
  updateCallUI();

  // Only offer "switch camera" if the device actually has more than one.
  try {
    const cams = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === "videoinput");
    $("flipCamBtn").classList.toggle("hidden", cams.length < 2);
  } catch { /* leave hidden */ }

  // Keep the screen on during a call (released automatically if the app is hidden).
  try { wakeLock = await navigator.wakeLock?.request("screen"); } catch { /* not supported - fine */ }
}

function endCall() {
  localStream?.getTracks().forEach((t) => t.stop());
  localStream = null;
  for (const entry of peers.values()) entry.peerLink.removeLocalStream();
  $("localVideo").srcObject = null;
  wakeLock?.release?.().catch(() => {});
  wakeLock = null;
  updateCallUI();
}

$("muteBtn").onclick = () => {
  micOn = !micOn;
  localStream?.getAudioTracks().forEach((t) => (t.enabled = micOn));
  refreshControlButtons();
};

$("camToggleBtn").onclick = () => {
  camOn = !camOn;
  localStream?.getVideoTracks().forEach((t) => (t.enabled = camOn));
  refreshControlButtons();
};

$("flipCamBtn").onclick = async () => {
  if (!localStream) return;
  const next = facing === "user" ? "environment" : "user";
  const oldTrack = localStream.getVideoTracks()[0];
  // Phones usually can't open two cameras at once - release the old one first.
  oldTrack?.stop();
  let newTrack;
  try {
    const s = await navigator.mediaDevices.getUserMedia({ video: { facingMode: next } });
    newTrack = s.getVideoTracks()[0];
    facing = next;
  } catch (err) {
    addSystemMessage("Couldn't switch camera: " + err.message);
    try {
      // put the original camera back so the call isn't left without video
      const s = await navigator.mediaDevices.getUserMedia({ video: { facingMode: facing } });
      newTrack = s.getVideoTracks()[0];
    } catch { return; }
  }
  newTrack.enabled = camOn;
  if (oldTrack) localStream.removeTrack(oldTrack);
  localStream.addTrack(newTrack);
  for (const entry of peers.values()) await entry.peerLink.replaceVideoTrack(newTrack);
  $("localVideo").srcObject = localStream;
  updateCallUI();
};

$("hangupBtn").onclick = endCall;
$("callBtn").onclick = startCall;
$("endCallBtn").onclick = endCall;
refreshControlButtons();
updateCallUI();

// Screen wake locks are released when the page is hidden - take it back on return.
document.addEventListener("visibilitychange", async () => {
  if (!document.hidden && localStream && !wakeLock) {
    try { wakeLock = await navigator.wakeLock?.request("screen"); } catch { /* ignore */ }
  }
});

// ---------- Leave ----------
// NOTE: this must NOT just reload the page. An invite/call link looks like
// index.html?room=CODE, and reloading it would auto-join the same room again
// (that was the "I can't leave" bug). Navigate to a clean URL instead.
$("leaveBtn").onclick = () => {
  localStream?.getTracks().forEach((t) => t.stop());
  localStream = null;
  for (const entry of peers.values()) entry.peerLink.close();
  peers.clear();
  socket?.emit("leave-room");
  socket?.disconnect();
  window.location.replace(cameFromMessages ? "messages.html" : "index.html");
};

// Android hardware Back button: in a room it asks before leaving (so a stray
// swipe can't drop you out of a call); on the start screen it returns to Messages.
setBackHandler(() => {
  if (closeMenus()) return true;
  if (!$("sharePanel").classList.contains("hidden")) {
    closeSharePanel();
    return true;
  }
  if (!screens.chat.classList.contains("hidden")) {
    if (confirm("Leave this room?")) $("leaveBtn").click();
    return true;
  }
  window.location.replace("messages.html");
  return true;
});

// 3-dot menu: every row has an icon AND text.
attachMenu($("menuBtn"), () => [
  { label: "Copy room code", icon: ICONS.copyText, onClick: async () => { if (await copyToClipboard(roomId)) addSystemMessage("Room code copied."); } },
  { label: "Share room", icon: ICONS.share, onClick: openSharePanel },
  { label: "Messages", icon: ICONS.chat, href: "messages.html" },
  { label: "Settings", icon: ICONS.settings, href: "settings.html" },
  { label: "Log out", icon: ICONS.logout, danger: true, onClick: logout },
]);

// ============================================================
// Share this room (opens automatically when you create one)
// ============================================================
function roomLink() {
  // In the Android app the page itself lives at https://localhost, which is
  // useless to anyone else - only build a link when we know the real server.
  const base = SERVER_URL || (isNative ? "" : window.location.origin);
  return base ? `${base}/index.html?room=${encodeURIComponent(roomId)}` : "";
}

function shareText() {
  const link = roomLink();
  return link
    ? `Join my private room on E2EE Chat.\nCode: ${roomId}\n${link}`
    : `Join my private room on E2EE Chat. Open the app, tap Join and enter the code: ${roomId}`;
}

function setInviteMsg(text, kind = "") {
  const el = $("inviteMsg");
  el.textContent = text;
  el.className = "invite-msg" + (kind ? " " + kind : "");
}

function openSharePanel() {
  if (!roomId) return;
  $("shareCode").textContent = roomId;
  setInviteMsg("");
  $("sharePanel").classList.remove("hidden");
  if (!isNative) $("inviteUsername").focus();
}

function closeSharePanel() {
  $("sharePanel").classList.add("hidden");
  $("textInput").focus();
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Older WebViews: fall back to a temporary textarea.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { /* ignore */ }
    ta.remove();
    return ok;
  }
}

async function shareRoomLink() {
  const text = shareText();
  try {
    const NativeShare = window.Capacitor?.Plugins?.Share;
    if (isNative && NativeShare) {
      await NativeShare.share({ title: "Join my room", text, dialogTitle: "Share room" });
      return;
    }
    if (navigator.share) {
      await navigator.share({ title: "Join my room", text });
      return;
    }
  } catch (err) {
    if (/cancel|abort/i.test(String(err))) return; // they just closed the share sheet
    console.warn("Share failed, copying instead:", err);
  }
  const ok = await copyToClipboard(text);
  setInviteMsg(ok ? "Link copied - paste it to anyone." : "Couldn't share. Code: " + roomId, ok ? "ok" : "err");
}

async function copyRoomLink() {
  const ok = await copyToClipboard(shareText());
  setInviteMsg(ok ? "Copied." : "Couldn't copy. Code: " + roomId, ok ? "ok" : "err");
}

function sendInvite() {
  const to = $("inviteUsername").value.trim().replace(/^@+/, "").toLowerCase();
  if (!to) return;
  if (!socket?.connected) return setInviteMsg("Not connected yet - try again in a moment.", "err");
  $("inviteSendBtn").disabled = true;
  setInviteMsg("Sending…");
  socket.timeout(8000).emit("room-invite", { to }, (err, res) => {
    $("inviteSendBtn").disabled = false;
    if (err) return setInviteMsg("No response from the server. Try again.", "err");
    if (!res?.ok) return setInviteMsg(res?.error || "Could not send the invite.", "err");
    setInviteMsg(`Invite sent to @${to}. They'll be notified.`, "ok");
    addSystemMessage(`Invited @${to} to this room.`);
    $("inviteUsername").value = "";
  });
}

$("shareBtn").onclick = openSharePanel;
$("shareCloseBtn").onclick = closeSharePanel;
$("sharePanel").addEventListener("click", (e) => { if (e.target === $("sharePanel")) closeSharePanel(); });
$("shareLinkBtn").onclick = shareRoomLink;
$("shareCopyBtn").onclick = copyRoomLink;
$("inviteSendBtn").onclick = sendInvite;
$("inviteUsername").addEventListener("keydown", (e) => { if (e.key === "Enter") sendInvite(); });

// ============================================================
// Reconnect / room-gone cleanup
// ============================================================
function formatDuration(seconds) {
  if (seconds % 60 === 0) {
    const m = seconds / 60;
    return m === 1 ? "1 minute" : `${m} minutes`;
  }
  return `${seconds} seconds`;
}

/** Drop every peer connection (used after a reconnect, before rejoining). */
function resetPeers() {
  for (const entry of peers.values()) {
    entry.peerLink.close();
    entry.videoEl?.remove();
  }
  peers.clear();
  incomingFiles.clear();
  $("fingerprintList").innerHTML = "";
  $("fingerprintBar").classList.add("hidden");
  updateHeaderStatus();
  updateCallUI();
}

/** The room no longer exists: erase everything this device holds about it. */
function wipeRoomState() {
  if (!hasJoined) return;
  localStream?.getTracks().forEach((t) => t.stop());
  localStream = null;
  wakeLock?.release?.().catch(() => {});
  wakeLock = null;
  resetPeers();
  $("localVideo").srcObject = null;
  $("messages").innerHTML = "";
  for (const url of blobUrls) URL.revokeObjectURL(url);
  blobUrls.clear();
  $("sharePanel").classList.add("hidden");
  keyPair = null;
  myPublicKeyB64 = null;
  roomId = null;
  hasJoined = false;
  updateCallUI();
}

// ============================================================
// Alerts for messages that arrive inside the room
// ============================================================
// These are P2P (the server never sees them), so they can only be raised by
// THIS device while its connection to the others is alive.
let blipCtx = null;
function playBlip() {
  try {
    blipCtx = blipCtx || new (window.AudioContext || window.webkitAudioContext)();
    blipCtx.resume?.();
    const osc = blipCtx.createOscillator();
    const gain = blipCtx.createGain();
    osc.frequency.value = 660;
    gain.gain.setValueAtTime(0.0001, blipCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.1, blipCtx.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, blipCtx.currentTime + 0.18);
    osc.connect(gain).connect(blipCtx.destination);
    osc.start();
    osc.stop(blipCtx.currentTime + 0.2);
  } catch { /* audio blocked - silent is fine */ }
  navigator.vibrate?.(60);
}

function alertIncoming(fromUsername, preview) {
  if (document.hidden) {
    // Built here, after decryption - this text never touches the server.
    notify({ title: `${fromUsername} · Room ${roomId}`, body: preview, extra: { roomCode: roomId, type: "room-message" }, channel: "messages" });
  } else {
    playBlip();
  }
}

onNotificationTap(() => window.focus());

// First tap: ask for notification permission (Android 13+ shows the system prompt) and register for push.
document.addEventListener("pointerdown", () => initNotifications(), { once: true });
