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
 *  2. QUICK ROOMS (unchanged from before): ad-hoc, code-based 1:1 sessions
 *     for live text/file/audio/video, fully peer-to-peer over WebRTC. This
 *     server only relays WebRTC handshake data (SDP/ICE) and one-time
 *     public keys — it never sees chat content, files, audio, or video.
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
  maxHttpBufferSize: 2e6,
  cors: { origin: ALLOWED_ORIGIN, methods: ["GET", "POST", "DELETE"] },
});
attachIO(io);

connectDB();

app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
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

// roomId -> Set of socket ids (max 2) — for the Quick Rooms feature only.
const rooms = new Map();

io.on("connection", (socket) => {
  // Personal room for real-time message delivery (routes/messages.js pushes
  // "new-message" / "message-deleted" events here when this user is online).
  socket.join(socket.user.username);

  let currentRoom = null;

  socket.on("join-room", (roomId) => {
    if (!roomId || typeof roomId !== "string" || roomId.length > 64) {
      socket.emit("room-error", "Invalid room code.");
      return;
    }

    const occupants = rooms.get(roomId) || new Set();

    if (occupants.size >= 2) {
      socket.emit("room-error", "This room already has two people in it.");
      return;
    }

    occupants.add(socket.id);
    rooms.set(roomId, occupants);
    socket.join(roomId);
    currentRoom = roomId;

    const isInitiator = occupants.size === 1;
    socket.emit("joined", { roomId, isInitiator });

    if (occupants.size === 2) {
      io.to(roomId).emit("peer-ready");
    }
  });

  // Generic relay: SDP offers/answers, ICE candidates, and public keys.
  // The server does not inspect, log, or interpret the payload contents.
  socket.on("signal", (payload) => {
    if (!currentRoom) return;
    socket.to(currentRoom).emit("signal", payload);
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
        io.to(currentRoom).emit("peer-left");
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
