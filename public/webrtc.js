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
 */

export class PeerLink {
  constructor(socket, remoteSocketId, remoteUsername, isInitiator) {
    this.socket = socket;
    this.remoteSocketId = remoteSocketId;
    this.remoteUsername = remoteUsername;
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
        this._sendSignal({ kind: "ice", candidate: e.candidate });
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

  _sendSignal(payload) {
    this.socket.emit("signal", { to: this.remoteSocketId, ...payload });
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
        this._sendSignal({ kind: "sdp", sdp: this.pc.localDescription });
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
    this._sendSignal({ kind: "sdp", sdp: this.pc.localDescription });
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
    this._sendSignal({ kind: "sdp", sdp: this.pc.localDescription });
  }

  close() {
    this.dataChannel?.close();
    this.pc.close();
  }
}
