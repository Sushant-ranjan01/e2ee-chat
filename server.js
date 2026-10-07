/**
 * E2EE Chat - Server
 * ------------------
 * Three jobs, kept deliberately separate:
 *
 *  1. AUTH (routes/auth.js + models/User.js): username + phone number +
 *     password accounts, backed by MongoDB. Passwords are hashed with
 *     bcrypt and never stored or logged in plain text. Each account also
 *     has a long-term public/private encryption keypair — the public half
 *     is stored plainly (that's safe), the private half is stored only in
 *     a form encrypted with a key derived from the user's password, which
 *     this server never has access to. See public/crypto.js for the scheme.
 *
 *  2. QUICK ROOMS: ad-hoc, code-based multi-person sessions (up to
 *     ROOM_MAX_SIZE people) for live text/emoji/file/audio/video, fully
 *     peer-to-peer over a WebRTC mesh — every pair of participants opens
 *     its own direct connection. This server only relays WebRTC handshake
 *     data (SDP/ICE) and one-time public keys, targeted at a specific peer;
 *     it never sees chat content, files, audio, or video.
 *
 *  3. MESSAGES (routes/messages.js + routes/users.js + models/Message.js):
 *     persistent, WhatsApp-style messaging by username, so two people don't
 *     need to be online at the same time. Every message is encrypted in the
 *     sender's browser directly to the recipient's public key before it's
 *     ever sent here (ECIES) — this server stores and forwards ciphertext
 *     it cannot read, and auto-deletes it after a configurable retention
 *     window (see models/Message.js). Either side can also delete a message
 *     outright at any time, for both of them.
 */

require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const cors = require("cors");
const { Server } = require("socket.io");

const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const usersRoutes = require("./routes/users");
const groupsRoutes = require("./routes/groups");
const { router: messagesRoutes, attachIO } = require("./routes/messages");
const { verifyToken } = require("./utils/token");

const app = express();
const server = http.createServer(app);

// Allow the frontend to call this server from a different origin — needed
// once the frontend is bundled inside the native app (Capacitor) or hosted
// separately from this backend. Restrict this via ALLOWED_ORIGIN in .env
// once you know your real frontend origin(s); "*" is fine for development.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";

const io = new Server(server, {
  maxHttpBufferSize: 10e6, // headroom for encrypted attachments (voice/image/file messages)
  cors: { origin: ALLOWED_ORIGIN, methods: ["GET", "POST", "DELETE"] },
});
attachIO(io);

connectDB();

app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
// Used by the app's "Server settings" to check an address is really this server.
app.get("/api/health", (req, res) => res.json({ ok: true }));
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/groups", groupsRoutes);
app.use("/api/messages", messagesRoutes);

// ---------- Socket.IO auth gate ----------
// No valid session token = no socket access at all.
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("unauthorized"));
  try {
    socket.user = verifyToken(token); // { username, phoneNumber, iat, exp }
    next();
  } catch {
    next(new Error("unauthorized"));
  }
});

// roomId -> Map<socketId, username> — for the Quick Rooms feature only.
// Rooms now support multiple people (mesh topology: every pair of
// participants opens its own direct WebRTC connection — see public/webrtc.js
// and public/app.js). ROOM_MAX_SIZE caps this because a full mesh's
// connection count grows quickly (N people = N*(N-1)/2 connections total,
// each person maintaining N-1 of them) — fine for a small group call, not
// designed to scale to a large one.
const ROOM_MAX_SIZE = Number(process.env.ROOM_MAX_SIZE) || 6;
const rooms = new Map();

// roomCode -> { from, targets:Set<username>, timer } — direct video calls that
// are still "ringing" (started from a chat thread in Messages). Only used so
// the ring can be dismissed when the caller hangs up first or someone picks
// up. Pure routing metadata; never any call content. Entries expire on their own.
const pendingCalls = new Map();
const CALL_RING_MS = 45 * 1000;
const ROOM_CODE_REGEX = /^[A-Za-z0-9]{4,12}$/;
function clearPendingCall(roomCode) {
  const p = pendingCalls.get(roomCode);
  if (p) clearTimeout(p.timer);
  pendingCalls.delete(roomCode);
}

// username -> count of currently-open sockets for that user (a person can
// have this app open in more than one tab/device at once). Online/offline
// is just "count > 0" - this is presence metadata only, never message
// content, so tracking it doesn't touch the encryption guarantees at all.
const onlineCounts = new Map();

io.on("connection", (socket) => {
  // Personal room for real-time message delivery (routes/messages.js pushes
  // "new-message" / "message-deleted" events here when this user is online).
  socket.join(socket.user.username);

  // ---------- Presence ----------
  const me = socket.user.username;
  const wasOffline = !onlineCounts.get(me);
  onlineCounts.set(me, (onlineCounts.get(me) || 0) + 1);
  if (wasOffline) {
    socket.broadcast.emit("presence-online", { username: me });
  }
  // Tell the newly-connected client who's online right now.
  socket.emit("presence-snapshot", { usernames: [...onlineCounts.keys()] });

  socket.on("disconnect", () => {
    const remaining = (onlineCounts.get(me) || 1) - 1;
    if (remaining <= 0) {
      onlineCounts.delete(me);
      socket.broadcast.emit("presence-offline", { username: me });
    } else {
      onlineCounts.set(me, remaining);
    }
  });

  // ---------- Typing indicator (Messages feature) ----------
  // Purely ephemeral - never stored, just relayed live to whoever should see
  // it. `to` is either one username (DM) or an array of usernames (group,
  // supplied by the sender's client since it already has the member list).
  socket.on("typing", ({ to }) => {
    if (!to) return;
    const targets = Array.isArray(to) ? to : [to];
    for (const username of targets) {
      if (username !== me) io.to(username).emit("typing", { from: me });
    }
  });

  // ---------- Direct calls from a chat thread (Messages feature) ----------
  // The caller's browser has already posted an end-to-end encrypted
  // "video call" invite into the thread (so it's in the chat history). This
  // extra, ephemeral event just makes the other person's phone/browser RING
  // right now if they're online. It carries only the room code and who's
  // calling — never any call content (that stays peer-to-peer in the room).
  let recentInvites = [];
  socket.on("call-invite", (payload, ack) => {
    const { to, roomCode, groupId } = payload || {};
    const done = typeof ack === "function" ? ack : () => {};

    if (!Array.isArray(to) || to.length === 0 || to.length > 50) return done();
    if (typeof roomCode !== "string" || !ROOM_CODE_REGEX.test(roomCode)) return done();

    // Simple anti-spam: max 5 rings per 30 seconds per connection.
    const now = Date.now();
    recentInvites = recentInvites.filter((t) => now - t < 30 * 1000);
    if (recentInvites.length >= 5) return done();
    recentInvites.push(now);

    const targets = [...new Set(to.filter((u) => typeof u === "string" && u && u !== me))];
    if (targets.length === 0) return done();

    clearPendingCall(roomCode.toUpperCase());
    const timer = setTimeout(() => pendingCalls.delete(roomCode.toUpperCase()), CALL_RING_MS);
    pendingCalls.set(roomCode.toUpperCase(), { from: me, targets: new Set(targets), timer });

    const safeGroupId = typeof groupId === "string" && groupId.length <= 64 ? groupId : undefined;
    for (const username of targets) {
      io.to(username).emit("incoming-call", { from: me, roomCode: roomCode.toUpperCase(), callType: "video", groupId: safeGroupId });
    }
    done();
  });

  socket.on("call-decline", ({ roomCode } = {}) => {
    if (typeof roomCode !== "string") return;
    const pending = pendingCalls.get(roomCode.toUpperCase());
    if (!pending || !pending.targets.has(me)) return;
    io.to(pending.from).emit("call-declined", { from: me, roomCode: roomCode.toUpperCase() });
  });

  let currentRoom = null;

  socket.on("join-room", (roomId) => {
    if (!roomId || typeof roomId !== "string" || roomId.length > 64) {
      socket.emit("room-error", "Invalid room code.");
      return;
    }

    const occupants = rooms.get(roomId) || new Map();

    if (occupants.size >= ROOM_MAX_SIZE) {
      socket.emit("room-error", `This room is full (max ${ROOM_MAX_SIZE} people).`);
      return;
    }

    // Tell the newcomer who's already here - the newcomer's browser will
    // initiate a WebRTC connection to each of them (see public/app.js).
    const existingPeers = [...occupants.entries()].map(([socketId, username]) => ({ socketId, username }));

    // Someone being rung just picked up (in this tab/device) - stop the
    // ring on their other open tabs/devices.
    const ringing = pendingCalls.get(roomId.toUpperCase());
    if (ringing && ringing.targets.has(me)) {
      ringing.targets.delete(me);
      io.to(me).emit("call-cancelled", { roomCode: roomId.toUpperCase() });
    }

    occupants.set(socket.id, socket.user.username);
    rooms.set(roomId, occupants);
    socket.join(roomId);
    currentRoom = roomId;

    socket.emit("joined", { roomId, existingPeers, maxSize: ROOM_MAX_SIZE });

    // Tell existing occupants a newcomer arrived - they wait for the
    // newcomer's offer rather than both sides racing to initiate.
    socket.to(roomId).emit("peer-joined", { socketId: socket.id, username: socket.user.username });
  });

  // Targeted relay: every signal now names exactly which peer it's for
  // (payload.to), since a room can have more than one other person in it.
  // The server does not inspect, log, or interpret the payload contents
  // beyond that routing address.
  socket.on("signal", (payload) => {
    if (!currentRoom || !payload?.to) return;
    io.to(payload.to).emit("signal", { ...payload, from: socket.id, fromUsername: socket.user.username });
  });

  socket.on("leave-room", () => cleanupRoom());
  socket.on("disconnect", () => cleanupRoom());

  function cleanupRoom() {
    if (!currentRoom) return;
    const occupants = rooms.get(currentRoom);
    if (occupants) {
      occupants.delete(socket.id);
      if (occupants.size === 0) {
        rooms.delete(currentRoom);
        // The caller left an empty room while the call was still ringing -
        // nobody is there to pick up anymore, so stop the ring.
        const ringing = pendingCalls.get(currentRoom.toUpperCase());
        if (ringing && ringing.from === me) {
          for (const username of ringing.targets) {
            io.to(username).emit("call-cancelled", { roomCode: currentRoom.toUpperCase() });
          }
          clearPendingCall(currentRoom.toUpperCase());
        }
      } else {
        socket.to(currentRoom).emit("peer-left", { socketId: socket.id });
      }
    }
    socket.leave(currentRoom);
    currentRoom = null;
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`E2EE chat server running on http://localhost:${PORT}`);
});
