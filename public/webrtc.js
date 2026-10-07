/**
 * webrtc.js — One PeerLink = one direct connection to ONE other participant.
 *
 * A Quick Room with more than 2 people uses a mesh topology: everyone opens
 * a separate PeerLink (and separate WebRTC connection) to every other
 * participant. There's no central media server — app.js creates one
 * PeerLink per remote participant and keeps them in a map keyed by that
 * participant's socket ID.
 *
 * Once connected, each PeerLink's DataChannel and media tracks travel
 * directly between those two browsers, encrypted in transit by DTLS-SRTP
 * (mandatory, built into WebRTC) — the signaling server is only used to
 * exchange the initial handshake (SDP/ICE) for each pair, addressed
 * specifically to that pair (see the `to`/`from` fields), never broadcast
 * to the whole room.
 *
 * Renegotiation uses the standard "perfect negotiation" pattern: media tracks
 * (a live video call) can be added or removed at any time, by either side,
 * including for people who join the room after the call has already started.
 */

export class PeerLink {
  constructor(socket, remoteSocketId, remoteUsername, isInitiator) {
    this.socket = socket;
    this.remoteSocketId = remoteSocketId;
    this.remoteUsername = remoteUsername;
    this.isInitiator = isInitiator;
    // Perfect negotiation roles: if both sides send an offer at the same
    // moment, the "polite" side (the one who was already in the room) backs off.
    this.polite = !isInitiator;
    this.pc = new RTCPeerConnection({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
      ],
    });
    this.dataChannel = null;
    this.onDataChannelMessage = null;
    this.onDataChannelOpen = null;
    this.onConnectionStateChange = null;
    this.onRemoteTrack = null;
    this._pendingIce = [];
    this._senders = [];
    this._makingOffer = false;
    this._ignoreOffer = false;
    this._queue = Promise.resolve(); // handle incoming signals strictly in order

    this.pc.onicecandidate = (e) => {
      if (e.candidate) {
        this._sendSignal({ kind: "ice", candidate: e.candidate });
      }
    };

    this.pc.onconnectionstatechange = () => {
      this.onConnectionStateChange?.(this.pc.connectionState);
    };

    this.pc.ontrack = (e) => {
      this.onRemoteTrack?.(e.streams[0] || new MediaStream([e.track]));
    };

    // Fires on its own when the data channel is created (initial offer) and
    // whenever tracks are added/removed (call started/ended).
    this.pc.onnegotiationneeded = async () => {
      try {
        this._makingOffer = true;
        const offer = await this.pc.createOffer();
        if (this.pc.signalingState !== "stable") return;
        await this.pc.setLocalDescription(offer);
        this._sendSignal({ kind: "sdp", sdp: this.pc.localDescription });
      } catch (err) {
        console.error("Negotiation failed:", err);
      } finally {
        this._makingOffer = false;
      }
    };

    if (isInitiator) {
      this.dataChannel = this.pc.createDataChannel("chat", { ordered: true });
      this._wireDataChannel(this.dataChannel);
    } else {
      this.pc.ondatachannel = (e) => {
        this.dataChannel = e.channel;
        this._wireDataChannel(this.dataChannel);
      };
    }
  }

  _sendSignal(payload) {
    this.socket.emit("signal", { to: this.remoteSocketId, ...payload });
  }

  _wireDataChannel(channel) {
    channel.binaryType = "arraybuffer";
    channel.onopen = () => this.onDataChannelOpen?.();
    channel.onmessage = (e) => this.onDataChannelMessage?.(e.data);
  }

  handleSignal(payload) {
    this._queue = this._queue.then(() => this._handleSignal(payload)).catch((err) => {
      console.error("Signal handling failed:", err);
    });
    return this._queue;
  }

  async _handleSignal(payload) {
    if (payload.kind === "sdp") {
      const desc = payload.sdp;
      const collision =
        desc.type === "offer" && (this._makingOffer || this.pc.signalingState !== "stable");
      this._ignoreOffer = !this.polite && collision;
      if (this._ignoreOffer) return;

      if (collision) {
        // Polite side: drop our own half-made offer and accept theirs.
        await Promise.all([
          this.pc.setLocalDescription({ type: "rollback" }),
          this.pc.setRemoteDescription(desc),
        ]);
      } else {
        await this.pc.setRemoteDescription(desc);
      }
      await this._flushIce();

      if (desc.type === "offer") {
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        this._sendSignal({ kind: "sdp", sdp: this.pc.localDescription });
      }
    } else if (payload.kind === "ice") {
      if (this.pc.remoteDescription) {
        try {
          await this.pc.addIceCandidate(payload.candidate);
        } catch (err) {
          if (!this._ignoreOffer) console.warn("ICE candidate rejected:", err);
        }
      } else {
        this._pendingIce.push(payload.candidate);
      }
    }
  }

  async _flushIce() {
    for (const c of this._pendingIce) {
      await this.pc.addIceCandidate(c).catch(() => {});
    }
    this._pendingIce = [];
  }

  send(data) {
    if (this.dataChannel && this.dataChannel.readyState === "open") {
      this.dataChannel.send(data);
      return true;
    }
    return false;
  }

  /** Simple backpressure helper for large file transfers. */
  async waitForBufferedAmountLow(threshold = 4 * 1024 * 1024) {
    if (!this.dataChannel) return;
    while (this.dataChannel.bufferedAmount > threshold) {
      await new Promise((r) => setTimeout(r, 30));
    }
  }

  /** Start sending our camera/mic to this peer (renegotiates automatically). */
  addLocalStream(stream) {
    for (const track of stream.getTracks()) {
      if (this._senders.some((s) => s.track === track)) continue;
      this._senders.push(this.pc.addTrack(track, stream));
    }
  }

  /** Swap the camera we send (front/back) without renegotiating. */
  async replaceVideoTrack(track) {
    const sender = this._senders.find((s) => s.track?.kind === "video" || s._wasVideo);
    if (sender) {
      sender._wasVideo = true;
      await sender.replaceTrack(track);
    }
  }

  /** Stop sending our camera/mic to this peer (renegotiates automatically). */
  removeLocalStream() {
    for (const sender of this._senders) {
      try { this.pc.removeTrack(sender); } catch { /* already closed */ }
    }
    this._senders = [];
  }

  close() {
    this.dataChannel?.close();
    this.pc.close();
  }
}
