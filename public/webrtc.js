/**
 * webrtc.js — Establishes a direct peer-to-peer connection between the two
 * browsers. Once connected, the DataChannel (chat/files) and any media
 * tracks (live call) travel BROWSER-TO-BROWSER, encrypted in transit by
 * DTLS-SRTP (mandatory, built into WebRTC itself) — the signaling server is
 * no longer in the data path at all for chat/file content.
 *
 * We still add our own AES-GCM layer on top (see crypto.js) so that content
 * is encrypted with a key that this app's server has never seen, rather than
 * relying solely on transport-level encryption.
 */

export class PeerLink {
  constructor(socket, roomId, isInitiator) {
    this.socket = socket;
    this.roomId = roomId;
    this.isInitiator = isInitiator;
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

    this.pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.socket.emit("signal", { kind: "ice", candidate: e.candidate });
      }
    };

    this.pc.onconnectionstatechange = () => {
      this.onConnectionStateChange?.(this.pc.connectionState);
    };

    this.pc.ontrack = (e) => {
      this.onRemoteTrack?.(e.streams[0]);
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

  _wireDataChannel(channel) {
    channel.binaryType = "arraybuffer";
    channel.onopen = () => this.onDataChannelOpen?.();
    channel.onmessage = (e) => this.onDataChannelMessage?.(e.data);
  }

  async handleSignal(payload) {
    if (payload.kind === "sdp") {
      const desc = new RTCSessionDescription(payload.sdp);
      if (desc.type === "offer") {
        await this.pc.setRemoteDescription(desc);
        await this._flushIce();
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        this.socket.emit("signal", { kind: "sdp", sdp: this.pc.localDescription });
      } else {
        await this.pc.setRemoteDescription(desc);
        await this._flushIce();
      }
    } else if (payload.kind === "ice") {
      if (this.pc.remoteDescription) {
        await this.pc.addIceCandidate(payload.candidate).catch(() => {});
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

  async createOffer() {
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    this.socket.emit("signal", { kind: "sdp", sdp: this.pc.localDescription });
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

  async addLocalStream(stream) {
    stream.getTracks().forEach((track) => this.pc.addTrack(track, stream));
    // Renegotiate since we added tracks after initial connection.
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    this.socket.emit("signal", { kind: "sdp", sdp: this.pc.localDescription });
  }

  close() {
    this.dataChannel?.close();
    this.pc.close();
  }
}
