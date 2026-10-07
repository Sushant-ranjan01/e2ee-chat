/**
 * call.js — Video calls started from inside a regular Messages thread.
 *
 * How it works (and how it differs from a Quick Room):
 *  - A Quick Room is something you *share a code for*. A call here is
 *    something that *rings the person you're already chatting with*.
 *  - The caller makes up a long random call ID, joins a signaling room with
 *    that ID, then asks the server to ring the other username(s)
 *    ("call-invite"). Whoever answers joins the same room; from there it's
 *    the same peer-to-peer WebRTC mesh Quick Rooms use (see webrtc.js), so
 *    audio/video flows directly between browsers, encrypted in transit by
 *    DTLS-SRTP, and never passes through the server.
 *  - The server only relays ringing events + WebRTC handshake data.
 *
 * Works for 1:1 threads and for group threads (everyone in the group is
 * rung; whoever picks up joins; capped by the server's ROOM_MAX_SIZE).
 */
import { PeerLink } from "./webrtc.js";
import { ICONS } from "./icons.js";

const $ = (id) => document.getElementById(id);
const RING_TIMEOUT_MS = 45_000;
const CONNECT_TIMEOUT_MS = 25_000; // answered, but media never came up
const CLOSE_DELAY_MS = 1600;

function randomCallId() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return "call_" + [...bytes].map((b) => chars[b % chars.length]).join("");
}

async function getCallMedia() {
  if (!navigator.mediaDevices?.getUserMedia || !window.RTCPeerConnection) {
    throw new Error("Calls need a browser with camera/microphone support (and HTTPS).");
  }
  try {
    return await navigator.mediaDevices.getUserMedia({ audio: true, video: { facingMode: "user" } });
  } catch (err) {
    // No camera (or it's busy)? Still allow a voice-only call.
    if (err.name === "NotAllowedError" || err.name === "SecurityError") {
      throw new Error("Camera/microphone permission was denied.");
    }
    try {
      return await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch {
      throw new Error("Couldn't access a camera or microphone: " + err.message);
    }
  }
}

export class CallManager {
  constructor({ myUsername }) {
    this.me = myUsername;
    this.socket = null;

    this.state = "idle"; // idle | calling | connecting | connected
    this.roomId = null;
    this.localStream = null;
    this.peers = new Map(); // socketId -> { link, username, tile, video }
    this.invitees = new Set(); // usernames we rang that haven't answered/declined yet
    this.isCaller = false;

    this.ringTimer = null;
    this.durationTimer = null;
    this.hideTimer = null;
    this.connectedAt = 0;

    this.incoming = null; // { from, roomId, groupName, timeoutId }

    this._wireUi();
  }

  /** Call once the Messages socket exists. */
  attach(socket) {
    this.socket = socket;

    socket.on("call-invite", (inv) => this._onInvite(inv));
    socket.on("call-cancelled", ({ roomId }) => {
      if (this.incoming?.roomId === roomId) this._dismissIncoming();
    });
    socket.on("call-handled", ({ roomId }) => {
      if (this.incoming?.roomId === roomId) this._dismissIncoming();
    });

    socket.on("call-invite-result", ({ roomId, reachable, unreachable }) => {
      if (roomId !== this.roomId || !this.isCaller) return;
      for (const u of unreachable) this.invitees.delete(u);
      if (reachable.length === 0) {
        const who = unreachable.length === 1 ? `@${unreachable[0]} is` : "Nobody is";
        this._end(`${who} offline right now`, { notifyPeers: false });
      }
    });

    socket.on("call-response", ({ from, roomId, accepted }) => {
      if (roomId !== this.roomId || !this.isCaller) return;
      if (!accepted) {
        this.invitees.delete(from);
        if (this.invitees.size === 0 && this.peers.size === 0) {
          this._end(`@${from} declined`, { notifyPeers: false });
        }
      }
    });

    // ----- room / WebRTC signaling (only relevant while in a call) -----
    socket.on("joined", ({ roomId, existingPeers }) => {
      if (roomId !== this.roomId) return;
      // We joined after these people, so we send the offers.
      for (const p of existingPeers) this._connectToPeer(p.socketId, p.username, true);
    });
    socket.on("peer-joined", ({ socketId, username }) => {
      if (!this.roomId) return;
      this.invitees.delete(username);
      this._connectToPeer(socketId, username, false); // they'll send the offer
    });
    socket.on("signal", async (payload) => {
      const entry = this.peers.get(payload.from);
      if (entry) await entry.link.handleSignal(payload).catch((e) => console.error("signal error", e));
    });
    socket.on("peer-left", ({ socketId }) => {
      const entry = this.peers.get(socketId);
      if (!entry) return;
      entry.link.close();
      entry.tile?.remove();
      this.peers.delete(socketId);
      if (this.peers.size === 0 && this.state !== "calling") {
        this._end("Call ended", { notifyPeers: false });
      }
    });
    socket.on("room-error", (msg) => {
      if (this.roomId) this._end(msg || "Couldn't join the call", { notifyPeers: false });
    });
  }

  // =====================================================================
  //  Starting a call
  // =====================================================================
  /**
   * @param {string[]} targets  usernames to ring
   * @param {string}   title    shown on the call screen ("@alice" / group name)
   * @param {string=}  groupName set for group calls so the callee sees which group
   */
  async startCall({ targets, title, groupName }) {
    if (this.state !== "idle") return;
    if (!this.socket?.connected) {
      alert("You're not connected right now — try again in a moment.");
      return;
    }
    if (!targets.length) {
      alert("There's nobody else to call in this conversation.");
      return;
    }

    try {
      this.localStream = await getCallMedia();
    } catch (err) {
      alert(err.message);
      return;
    }

    this.isCaller = true;
    this.roomId = randomCallId();
    this.invitees = new Set(targets);
    this.state = "calling";

    this._showOverlay(title, "Calling…");
    this.socket.emit("join-room", this.roomId);
    this.socket.emit("call-invite", { to: targets, roomId: this.roomId, groupName: groupName || null });

    this.ringTimer = setTimeout(() => {
      if (this.state !== "calling") return;
      // Someone joined but media never connected vs. nobody picked up.
      this._end(this.peers.size > 0 ? "Couldn't connect" : "No answer", { notifyPeers: true });
    }, RING_TIMEOUT_MS);
  }

  // =====================================================================
  //  Incoming calls
  // =====================================================================
  _onInvite({ from, roomId, groupName }) {
    // Already on a call, or already ringing for another one: politely decline.
    if (this.state !== "idle" || this.incoming) {
      this.socket.emit("call-response", { to: from, roomId, accepted: false });
      return;
    }
    const timeoutId = setTimeout(() => this._dismissIncoming(), RING_TIMEOUT_MS + 5000);
    this.incoming = { from, roomId, groupName, timeoutId };

    $("incomingAvatar").textContent = from.slice(0, 2).toUpperCase();
    $("incomingName").textContent = groupName ? groupName : `@${from}`;
    $("incomingSub").textContent = groupName ? `@${from} is starting a group video call` : "Incoming video call";
    $("incomingCall").classList.remove("hidden");
    navigator.vibrate?.([300, 150, 300]);
  }

  _dismissIncoming() {
    if (!this.incoming) return;
    clearTimeout(this.incoming.timeoutId);
    this.incoming = null;
    $("incomingCall").classList.add("hidden");
  }

  async _acceptIncoming() {
    const inv = this.incoming;
    if (!inv) return;
    this._dismissIncoming();

    try {
      this.localStream = await getCallMedia();
    } catch (err) {
      this.socket.emit("call-response", { to: inv.from, roomId: inv.roomId, accepted: false });
      alert(err.message);
      return;
    }

    this.isCaller = false;
    this.roomId = inv.roomId;
    this.state = "connecting";
    this._showOverlay(inv.groupName || `@${inv.from}`, "Connecting…");

    this.socket.emit("call-response", { to: inv.from, roomId: inv.roomId, accepted: true });
    this.socket.emit("join-room", this.roomId);

    // If the caller hung up in the meantime (or the connection never comes
    // up), don't leave this person staring at "Connecting…" forever.
    this.ringTimer = setTimeout(() => {
      if (this.state === "connecting") this._end("Couldn't connect", { notifyPeers: false });
    }, CONNECT_TIMEOUT_MS);
  }

  _declineIncoming() {
    const inv = this.incoming;
    if (!inv) return;
    this._dismissIncoming();
    this.socket.emit("call-response", { to: inv.from, roomId: inv.roomId, accepted: false });
  }

  // =====================================================================
  //  Peer connections
  // =====================================================================
  _connectToPeer(socketId, username, isInitiator) {
    if (this.peers.has(socketId)) return;
    const link = new PeerLink(this.socket, socketId, username, isInitiator);
    const entry = { link, username, tile: null, video: null };
    this.peers.set(socketId, entry);

    // Add our camera/mic BEFORE negotiating, so the very first offer/answer
    // already carries media (no renegotiation needed).
    this.localStream?.getTracks().forEach((t) => link.pc.addTrack(t, this.localStream));

    link.onRemoteTrack = (stream) => {
      if (!entry.tile) {
        const tile = document.createElement("div");
        tile.className = "call-tile";
        const video = document.createElement("video");
        video.autoplay = true;
        video.playsInline = true;
        const name = document.createElement("span");
        name.className = "call-tile-name";
        name.textContent = `@${username}`;
        tile.append(video, name);
        $("callGrid").appendChild(tile);
        entry.tile = tile;
        entry.video = video;
      }
      entry.video.srcObject = stream;
      entry.video.play?.().catch(() => {});
      this._markConnected();
    };
    link.onConnectionStateChange = (st) => {
      if (st === "connected") this._markConnected();
      if (st === "failed") {
        entry.tile?.querySelector(".call-tile-name")?.append(" (connection lost)");
      }
    };

    if (this.state === "calling") this._setStatus("Connecting…");
    if (isInitiator) link.createOffer().catch((e) => console.error("offer failed", e));
  }

  _markConnected() {
    if (this.state === "connected") return;
    this.state = "connected";
    clearTimeout(this.ringTimer);
    this.connectedAt = Date.now();
    this._tickDuration();
    this.durationTimer = setInterval(() => this._tickDuration(), 1000);
  }

  _tickDuration() {
    const s = Math.floor((Date.now() - this.connectedAt) / 1000);
    const mm = String(Math.floor(s / 60)).padStart(2, "0");
    const ss = String(s % 60).padStart(2, "0");
    this._setStatus(`${mm}:${ss}`);
  }

  // =====================================================================
  //  Ending a call
  // =====================================================================
  _end(reason, { notifyPeers }) {
    if (this.state === "idle") return;

    // Stop ringing anyone who hasn't answered yet.
    if (notifyPeers && this.isCaller && this.invitees.size && this.socket) {
      this.socket.emit("call-cancel", { to: [...this.invitees], roomId: this.roomId });
    }

    clearTimeout(this.ringTimer);
    clearInterval(this.durationTimer);
    for (const entry of this.peers.values()) {
      entry.link.close();
      entry.tile?.remove();
    }
    this.peers.clear();
    this.localStream?.getTracks().forEach((t) => t.stop());
    this.localStream = null;
    $("callLocalVideo").srcObject = null;

    this.socket?.emit("leave-room");

    this.state = "idle";
    this.roomId = null;
    this.isCaller = false;
    this.invitees.clear();

    // Show the reason briefly, then close the overlay.
    this._setStatus(reason);
    $("callControls").classList.add("hidden");
    clearTimeout(this.hideTimer);
    this.hideTimer = setTimeout(() => $("callOverlay").classList.add("hidden"), CLOSE_DELAY_MS);
  }

  /** Public: hang up now (used by the End button). */
  hangUp() {
    this._end("Call ended", { notifyPeers: true });
  }

  // =====================================================================
  //  UI
  // =====================================================================
  _wireUi() {
    $("callMuteBtn").innerHTML = ICONS.mic;
    $("callCamBtn").innerHTML = ICONS.video;
    $("callEndBtn").innerHTML = ICONS.phoneOff;
    $("declineCallBtn").innerHTML = ICONS.phoneOff;
    $("acceptCallBtn").innerHTML = ICONS.video;

    $("callEndBtn").onclick = () => this.hangUp();
    $("declineCallBtn").onclick = () => this._declineIncoming();
    $("acceptCallBtn").onclick = () => this._acceptIncoming();

    $("callMuteBtn").onclick = () => {
      const tracks = this.localStream?.getAudioTracks() || [];
      if (!tracks.length) return;
      const nowEnabled = !tracks[0].enabled;
      tracks.forEach((t) => (t.enabled = nowEnabled));
      $("callMuteBtn").innerHTML = nowEnabled ? ICONS.mic : ICONS.micOff;
      $("callMuteBtn").classList.toggle("off", !nowEnabled);
      $("callMuteBtn").title = nowEnabled ? "Mute" : "Unmute";
    };

    $("callCamBtn").onclick = () => {
      const tracks = this.localStream?.getVideoTracks() || [];
      if (!tracks.length) return;
      const nowEnabled = !tracks[0].enabled;
      tracks.forEach((t) => (t.enabled = nowEnabled));
      $("callCamBtn").innerHTML = nowEnabled ? ICONS.video : ICONS.videoOff;
      $("callCamBtn").classList.toggle("off", !nowEnabled);
      $("callCamBtn").title = nowEnabled ? "Turn camera off" : "Turn camera on";
    };
  }

  _showOverlay(title, status) {
    clearTimeout(this.hideTimer);
    $("callTitle").textContent = title;
    $("callGrid").innerHTML = "";
    $("callLocalVideo").srcObject = this.localStream;

    // Reset the control buttons to their "on" state for a fresh call.
    $("callMuteBtn").innerHTML = ICONS.mic;
    $("callMuteBtn").classList.remove("off");
    $("callMuteBtn").title = "Mute";
    $("callCamBtn").innerHTML = ICONS.video;
    $("callCamBtn").classList.remove("off");
    $("callCamBtn").title = "Turn camera off";
    const hasVideo = (this.localStream?.getVideoTracks().length || 0) > 0;
    $("callCamBtn").classList.toggle("hidden", !hasVideo);
    $("callLocalVideo").classList.toggle("hidden", !hasVideo);

    $("callControls").classList.remove("hidden");
    this._setStatus(status);
    $("callOverlay").classList.remove("hidden");
  }

  _setStatus(text) {
    $("callStatus").textContent = text;
  }
}
