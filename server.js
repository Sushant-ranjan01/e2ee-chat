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
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const http = require("http");
const path = require("path");
const cors = require("cors");
const { Server } = require("socket.io");

const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const usersRoutes = require("./routes/users");
const groupsRoutes = require("./routes/groups");
const pushRoutes = require("./routes/push");
const keysRoutes = require("./routes/keys");
const User = require("./models/User");
const { sendPushToUser } = require("./config/push");
const presence = require("./utils/presence");
const prefs = require("./utils/prefs");
const { router: messagesRoutes, attachIO } = require("./routes/messages");
const { verifyToken, IS_PROD } = require("./utils/token");

const app = express();
const server = http.createServer(app);

// ---------- Security hardening ----------
app.disable("x-powered-by");
// Behind a host's load balancer (Render, Railway, Heroku...) the real client
// address is in X-Forwarded-For. Without this, rate limits would treat every
// user as one IP. Set TRUST_PROXY=0 if you expose Node directly.
app.set("trust proxy", Number(process.env.TRUST_PROXY ?? (IS_PROD ? 1 : 0)));

// HTTPS only in production: browsers are redirected, API calls are refused.
if (IS_PROD && process.env.FORCE_HTTPS !== "0") {
  app.use((req, res, next) => {
    if (req.secure || req.path === "/api/health") return next();
    if (req.method === "GET" || req.method === "HEAD") {
      return res.redirect(308, `https://${process.env.PUBLIC_HOST || req.headers.host}${req.originalUrl}`);
    }
    res.status(403).json({ error: "HTTPS is required." });
  });
}

// CORS allow-list. ALLOWED_ORIGIN = comma-separated list of the exact web
// origins that may call this API, e.g. "https://chat.example.com". The Android
// app's own origins are always allowed. In production a missing/"*" value is
// treated as "only the Android app"; in development "*" stays open.
const NATIVE_ORIGINS = ["https://localhost", "capacitor://localhost", "http://localhost"];
const configuredOrigins = (process.env.ALLOWED_ORIGIN || "").split(",").map((o) => o.trim()).filter(Boolean);
const openCors = configuredOrigins.length === 0 || configuredOrigins.includes("*");
if (IS_PROD && openCors) {
  console.warn("WARNING: ALLOWED_ORIGIN is not set - only the Android app (and same-site pages) can call the API. Set ALLOWED_ORIGIN=https://your-site.example.com to allow other sites.");
}
const allowedOrigins = new Set([...configuredOrigins.filter((o) => o !== "*"), ...NATIVE_ORIGINS]);
const corsOrigin = (origin, cb) => cb(null, !origin || (!IS_PROD && openCors) || allowedOrigins.has(origin));

app.use(
  helmet({
    // Strict CSP: only this site's own scripts run (no inline scripts - they were
    // moved into *-init.js files). Set CSP_REPORT_ONLY=1 to log instead of block.
    contentSecurityPolicy: {
      useDefaults: false,
      reportOnly: process.env.CSP_REPORT_ONLY === "1",
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "blob:"],
        "media-src": ["'self'", "blob:", "data:"],
        "font-src": ["'self'", "data:"],
        "connect-src": ["'self'", "ws:", "wss:", "blob:"],
        "worker-src": ["'self'"],
        "manifest-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
        ...(IS_PROD ? { "upgrade-insecure-requests": [] } : {}),
      },
    },
    hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true } : false,
    crossOriginEmbedderPolicy: false,
  })
);
app.use((req, res, next) => {
  // Camera/mic are needed for calls; everything else the app never uses is off.
  res.setHeader("Permissions-Policy", "camera=(self), microphone=(self), geolocation=(), payment=(), usb=(), interest-cohort=()");
  next();
});

const io = new Server(server, {
  maxHttpBufferSize: 10e6, // headroom for encrypted attachments (voice/image/file messages)
  cors: { origin: corsOrigin, methods: ["GET", "POST", "DELETE"] },
});
attachIO(io);

connectDB();

app.use(cors({ origin: corsOrigin }));
// Encrypted attachments can be several MB; everything else is tiny.
app.use("/api/messages", express.json({ limit: "12mb" }));
app.use(express.json({ limit: "200kb" }));
app.use(express.static(path.join(__dirname, "public")));
// Used by the app's "Server settings" to check an address is really this server.
app.get("/api/health", (req, res) => res.json({ ok: true }));

// API responses are personal - never let a browser or proxy cache them.
app.use("/api", (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});
// A general ceiling per network address (login/registration/key requests have
// their own, stricter limits on top of this).
app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.API_RATE_LIMIT) || 1500,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests. Please slow down." },
  })
);
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/groups", groupsRoutes);
app.use("/api/push", pushRoutes);
app.use("/api/keys", keysRoutes);
app.use("/api/messages", messagesRoutes);

// ---------- Socket.IO auth gate ----------
// No valid session token = no socket access at all.
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("unauthorized"));
  try {
    socket.user = verifyToken(token); // { username, phoneNumber, iat, exp }
  } catch {
    return next(new Error("unauthorized"));
  }
  await prefs.load(socket.user.username); // blocks + "hide my online status", enforced below
  next();
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

// ---------- Quick Room lifetime ----------
// A room is created when someone starts it, and is DELETED COMPLETELY once it
// has been empty for ROOM_EMPTY_TTL_SECONDS (default 2 minutes). During that
// grace period the same code still works (e.g. a phone that dropped its
// connection can come back). After it, the code is gone for good: joining it
// says "expired" and everything the server held about it is erased.
//
// roomId -> { createdBy, createdAt, invited:Set<username>, expireTimer }
const ROOM_EMPTY_TTL_MS = (Number(process.env.ROOM_EMPTY_TTL_SECONDS) || 120) * 1000;
const roomMeta = new Map();

function destroyRoom(roomId) {
  const meta = roomMeta.get(roomId);
  if (meta) {
    clearTimeout(meta.expireTimer);
    // Tell anyone who was invited (and might still be showing the invite) that it's gone.
    for (const username of meta.invited) io.to(username).emit("room-expired", { roomCode: roomId });
  }
  roomMeta.delete(roomId);
  rooms.delete(roomId);
  clearPendingCall(roomId);
  // (deliberately no room code in the log - rooms are private)
  console.log("A room expired and was deleted.");
}

function scheduleRoomExpiry(roomId) {
  const meta = roomMeta.get(roomId);
  if (!meta) return;
  clearTimeout(meta.expireTimer);
  meta.expireTimer = setTimeout(() => {
    // Re-check: only delete if it's still empty.
    if ((rooms.get(roomId)?.size || 0) === 0) destroyRoom(roomId);
  }, ROOM_EMPTY_TTL_MS);
}

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

// ---------- Presence, filtered per viewer ----------
// Someone who turned off "show my online status" never appears online to
// anyone; blocked people never see each other's status either. This is
// decided HERE on the server - not just hidden in the UI - so it can't be
// peeked at by a modified client.
function onlineFor(viewer) {
  return [...onlineCounts.keys()].filter((u) => u === viewer || prefs.canSeeStatus(viewer, u));
}
function tellViewers(target, event) {
  for (const [, s] of io.sockets.sockets) {
    const viewer = s.user?.username;
    if (viewer && viewer !== target && prefs.canSeeStatus(viewer, target)) s.emit(event, { username: target });
  }
}
// A setting changed (hide status / block / unblock): give everyone a fresh,
// correctly-filtered view of who is online.
prefs.setOnChange(() => {
  for (const [, s] of io.sockets.sockets) {
    const viewer = s.user?.username;
    if (viewer) s.emit("presence-snapshot", { usernames: onlineFor(viewer) });
  }
});

io.on("connection", (socket) => {
  // Personal room for real-time message delivery (routes/messages.js pushes
  // "new-message" / "message-deleted" events here when this user is online).
  socket.join(socket.user.username);

  // ---------- Presence ----------
  const me = socket.user.username;
  // A fresh connection means the app is open. The client tells us when it goes
  // to the background (see "app-state") so we know when a push is needed.
  presence.setForeground(me, socket.id, true);
  socket.on("app-state", ({ active } = {}) => presence.setForeground(me, socket.id, !!active));
  const wasOffline = !onlineCounts.get(me);
  onlineCounts.set(me, (onlineCounts.get(me) || 0) + 1);
  if (wasOffline) tellViewers(me, "presence-online");
  // Tell the newly-connected client who's online right now (only people who
  // allow it, and never anyone who blocked them / they blocked).
  socket.emit("presence-snapshot", { usernames: onlineFor(me) });

  socket.on("disconnect", () => {
    presence.removeSocket(me, socket.id);
    const remaining = (onlineCounts.get(me) || 1) - 1;
    if (remaining <= 0) {
      onlineCounts.delete(me);
      tellViewers(me, "presence-offline");
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
      if (username !== me && !prefs.isBlockedEitherWay(me, username)) io.to(username).emit("typing", { from: me });
    }
  });

  // ---------- Direct calls from a chat thread (Messages feature) ----------
  // The caller's browser has already posted an end-to-end encrypted
  // "video call" invite into the thread (so it's in the chat history). This
  // extra, ephemeral event just makes the other person's phone/browser RING
  // right now if they're online. It carries only the room code and who's
  // calling — never any call content (that stays peer-to-peer in the room).
  let recentInvites = [];
  socket.on("call-invite", async (payload, ack) => {
    const { to, roomCode, groupId } = payload || {};
    const done = typeof ack === "function" ? ack : () => {};

    if (!Array.isArray(to) || to.length === 0 || to.length > 50) return done();
    if (typeof roomCode !== "string" || !ROOM_CODE_REGEX.test(roomCode)) return done();

    // Simple anti-spam: max 5 rings per 30 seconds per connection.
    const now = Date.now();
    recentInvites = recentInvites.filter((t) => now - t < 30 * 1000);
    if (recentInvites.length >= 5) return done();
    recentInvites.push(now);

    let targets = [...new Set(to.filter((u) => typeof u === "string" && u && u !== me))];
    // Never ring someone who blocked you (or whom you blocked).
    await Promise.all(targets.map((u) => prefs.load(u)));
    targets = targets.filter((u) => !prefs.isBlockedEitherWay(me, u));
    if (targets.length === 0) return done();

    clearPendingCall(roomCode.toUpperCase());
    const timer = setTimeout(() => pendingCalls.delete(roomCode.toUpperCase()), CALL_RING_MS);
    pendingCalls.set(roomCode.toUpperCase(), { from: me, targets: new Set(targets), timer });

    const safeGroupId = typeof groupId === "string" && groupId.length <= 64 ? groupId : undefined;
    for (const username of targets) {
      io.to(username).emit("incoming-call", { from: me, roomCode: roomCode.toUpperCase(), callType: "video", groupId: safeGroupId });
      // Phone not open in the foreground? Ring it through push too.
      if (!presence.isForeground(username)) {
        sendPushToUser(username, {
          title: "Incoming video call",
          body: `${me} is calling you`,
          channel: "calls",
          tag: "call-" + roomCode.toUpperCase(),
          ttlSeconds: 45,
          data: { type: "call", from: me, roomCode: roomCode.toUpperCase(), groupId: safeGroupId || "" },
        });
      }
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

  // Payload: { roomId, create } (a bare string is still accepted).
  //   create:true  -> start this room if it doesn't exist (the person who made it)
  //   otherwise    -> the room must already exist and not be expired
  socket.on("join-room", (payload) => {
    const rawId = typeof payload === "string" ? payload : payload?.roomId;
    const wantsCreate = typeof payload === "object" && payload?.create === true;

    if (!rawId || typeof rawId !== "string" || rawId.length > 64) {
      socket.emit("room-error", "Invalid room code.");
      return;
    }
    const roomId = rawId.toUpperCase();

    // Already in this very room on this socket (client re-sent join): ignore.
    if (currentRoom === roomId) return;
    if (currentRoom) cleanupRoom();

    // Unknown / expired code: only the creator (create:true) or someone being
    // rung for a call may bring a room into existence.
    if (!roomMeta.has(roomId)) {
      if (!wantsCreate && !pendingCalls.has(roomId)) {
        socket.emit("room-error", "This room doesn't exist or has expired. Ask for a new link.", { expired: true });
        socket.emit("room-expired", { roomCode: roomId });
        return;
      }
      roomMeta.set(roomId, { createdBy: me, createdAt: Date.now(), invited: new Set(), expireTimer: null });
    }

    const occupants = rooms.get(roomId) || new Map();

    if (occupants.size >= ROOM_MAX_SIZE) {
      socket.emit("room-error", `This room is full (max ${ROOM_MAX_SIZE} people).`);
      return;
    }

    // Someone is here again: cancel any pending deletion.
    clearTimeout(roomMeta.get(roomId).expireTimer);

    // Tell the newcomer who's already here - the newcomer's browser will
    // initiate a WebRTC connection to each of them (see public/app.js).
    const existingPeers = [...occupants.entries()].map(([socketId, username]) => ({ socketId, username }));

    // Someone being rung just picked up (in this tab/device) - stop the
    // ring on their other open tabs/devices.
    const ringing = pendingCalls.get(roomId);
    if (ringing && ringing.targets.has(me)) {
      ringing.targets.delete(me);
      io.to(me).emit("call-cancelled", { roomCode: roomId });
    }

    occupants.set(socket.id, socket.user.username);
    rooms.set(roomId, occupants);
    socket.join(roomId);
    currentRoom = roomId;

    socket.emit("joined", {
      roomId,
      existingPeers,
      maxSize: ROOM_MAX_SIZE,
      createdByMe: roomMeta.get(roomId).createdBy === me && existingPeers.length === 0,
      emptyTtlSeconds: Math.round(ROOM_EMPTY_TTL_MS / 1000),
    });

    // Tell existing occupants a newcomer arrived - they wait for the
    // newcomer's offer rather than both sides racing to initiate.
    socket.to(roomId).emit("peer-joined", { socketId: socket.id, username: socket.user.username });
  });

  // ---------- Share a room with a specific person, right from inside it ----------
  // Only someone who is IN the room can invite. The invite carries just the room
  // code and who it's from (never any chat content). If the person isn't looking
  // at the app, they get a push notification too.
  let recentRoomInvites = [];
  socket.on("room-invite", async (payload, ack) => {
    const done = typeof ack === "function" ? ack : () => {};
    try {
      if (!currentRoom) return done({ ok: false, error: "Join the room first." });
      const target = String(payload?.to || "").trim().replace(/^@+/, "").toLowerCase();
      if (!/^[a-z0-9_]{1,20}$/.test(target)) return done({ ok: false, error: "Enter a valid username." });
      if (target === me) return done({ ok: false, error: "That's you." });

      const now = Date.now();
      recentRoomInvites = recentRoomInvites.filter((t) => now - t < 60 * 1000);
      if (recentRoomInvites.length >= 10) return done({ ok: false, error: "Too many invites - wait a minute." });
      recentRoomInvites.push(now);

      const exists = await User.exists({ username: target });
      if (!exists) return done({ ok: false, error: `No user named "${target}".` });
      await prefs.load(target);
      if (prefs.get(me).blocked.has(target)) return done({ ok: false, error: `You blocked @${target}. Unblock them first.` });
      // They blocked you: look successful, deliver nothing (a block shouldn't be detectable).
      if (prefs.get(target).blocked.has(me)) return done({ ok: true });

      const roomCode = currentRoom;
      roomMeta.get(roomCode)?.invited.add(target);
      io.to(target).emit("room-invite", { from: me, roomCode });

      if (!presence.isForeground(target)) {
        sendPushToUser(target, {
          title: `${me} invited you to a room`,
          body: "Tap to join the Quick Room",
          channel: "messages",
          tag: "room-" + roomCode,
          data: { type: "room-invite", from: me, roomCode },
        });
      }
      done({ ok: true });
    } catch (err) {
      console.error(err);
      done({ ok: false, error: "Could not send the invite." });
    }
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
        // Empty: keep the code valid for a short grace period, then erase it.
        scheduleRoomExpiry(currentRoom);
        // The caller left an empty room while the call was still ringing -
        // nobody is there to pick up anymore, so stop the ring.
        const ringing = pendingCalls.get(currentRoom);
        if (ringing && ringing.from === me) {
          for (const username of ringing.targets) {
            io.to(username).emit("call-cancelled", { roomCode: currentRoom });
          }
          clearPendingCall(currentRoom);
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
