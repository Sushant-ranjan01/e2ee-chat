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

  // ---------- Calls started from inside a Messages thread ----------
  // Ringing only: the server relays "someone is calling you" / "answered" /
  // "declined" / "cancelled" between usernames. The call itself then happens
  // in an ordinary signaling room (join-room / signal below), so media still
  // travels peer-to-peer (DTLS-SRTP) and never touches this server.
  const CALL_ID_REGEX = /^[A-Za-z0-9_-]{8,64}$/;
  let lastInviteAt = 0;

  const cleanUsernames = (to) =>
    (Array.isArray(to) ? to : [to])
      .filter((u) => typeof u === "string" && u && u !== me)
      .slice(0, ROOM_MAX_SIZE - 1);

  socket.on("call-invite", ({ to, roomId, groupName } = {}) => {
    if (!CALL_ID_REGEX.test(String(roomId || ""))) return;
    const now = Date.now();
    if (now - lastInviteAt < 1500) return; // basic ring-spam throttle
    lastInviteAt = now;

    const reachable = [];
    const unreachable = [];
    for (const username of cleanUsernames(to)) {
      if (onlineCounts.has(username)) {
        io.to(username).emit("call-invite", {
          from: me,
          roomId,
          groupName: typeof groupName === "string" ? groupName.slice(0, 60) : null,
        });
        reachable.push(username);
      } else {
        unreachable.push(username);
      }
    }
    socket.emit("call-invite-result", { roomId, reachable, unreachable });
  });

  socket.on("call-response", ({ to, roomId, accepted } = {}) => {
    if (typeof to !== "string" || !CALL_ID_REGEX.test(String(roomId || ""))) return;
    io.to(to).emit("call-response", { from: me, roomId, accepted: !!accepted });
    // Stop the call ringing on this user's other tabs/devices too.
    socket.to(me).emit("call-handled", { roomId });
  });

  socket.on("call-cancel", ({ to, roomId } = {}) => {
    if (!CALL_ID_REGEX.test(String(roomId || ""))) return;
    for (const username of cleanUsernames(to)) {
      io.to(username).emit("call-cancelled", { from: me, roomId });
    }
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
