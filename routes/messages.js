const express = require("express");
const router = express.Router();
const Message = require("../models/Message");
const User = require("../models/User");
const Group = require("../models/Group");
const { requireAuth } = require("../middleware/authMiddleware");

// io is attached by server.js so we can push real-time delivery to whoever's
// currently online, without this route file needing to know about the
// socket server's internals.
let ioInstance = null;
function attachIO(io) {
  ioInstance = io;
}

// Ciphertext is base64, which runs ~33% larger than the original bytes.
// This caps roughly how big one recipient's encrypted copy can be — mainly
// a guard against abuse, not a hard product limit. Comfortably covers
// photos, voice notes, and most documents.
const MAX_CIPHERTEXT_BASE64_LENGTH = 8 * 1024 * 1024; // ~6MB of original data

function validBlob(b) {
  return (
    b &&
    typeof b.username === "string" &&
    typeof b.ephemeralPublicKey === "string" &&
    typeof b.iv === "string" &&
    typeof b.ciphertext === "string" &&
    b.ciphertext.length <= MAX_CIPHERTEXT_BASE64_LENGTH
  );
}

function deliveryStatusFor(recipients, me) {
  const others = recipients.filter((r) => r.username !== me);
  if (others.length === 0) return null;
  const readCount = others.filter((r) => r.read).length;
  return { read: readCount === others.length, readCount, totalCount: others.length };
}

router.post("/send", requireAuth, async (req, res) => {
  try {
    const { recipientUsername, groupId, recipients } = req.body || {};
    const me = req.user.username;

    if (!Array.isArray(recipients) || recipients.length === 0 || !recipients.every(validBlob)) {
      return res.status(400).json({ error: "Missing, malformed, or oversized message fields." });
    }
    if (!recipients.some((r) => r.username === me)) {
      return res.status(400).json({ error: "Message must include your own encrypted copy." });
    }

    let messageDoc;

    if (groupId) {
      const group = await Group.findById(groupId);
      if (!group) return res.status(404).json({ error: "Group not found." });
      if (!group.members.includes(me)) return res.status(403).json({ error: "Not a member of this group." });

      const recipientUsernames = new Set(recipients.map((r) => r.username));
      const missingMember = group.members.find((m) => !recipientUsernames.has(m));
      if (missingMember) {
        return res.status(400).json({ error: `Missing encrypted copy for group member: ${missingMember}` });
      }

      messageDoc = await Message.create({ senderUsername: me, groupId, recipients });
    } else {
      const cleanRecipient = String(recipientUsername || "").trim().toLowerCase();
      if (!cleanRecipient || cleanRecipient === me) {
        return res.status(400).json({ error: "Invalid recipient." });
      }
      const recipientUser = await User.findOne({ username: cleanRecipient }).select("username").lean();
      if (!recipientUser) return res.status(404).json({ error: "No user with that username." });

      const usernames = recipients.map((r) => r.username).sort();
      const expected = [me, cleanRecipient].sort();
      if (usernames.length !== 2 || usernames[0] !== expected[0] || usernames[1] !== expected[1]) {
        return res.status(400).json({ error: "Recipients must be exactly you and the other person." });
      }

      messageDoc = await Message.create({ senderUsername: me, recipientUsername: cleanRecipient, recipients });
    }

    const payload = {
      id: messageDoc._id,
      senderUsername: messageDoc.senderUsername,
      recipientUsername: messageDoc.recipientUsername,
      groupId: messageDoc.groupId,
      createdAt: messageDoc.createdAt,
    };

    // Real-time push to everyone in the recipients list who's currently
    // online (each socket joined a room named after their username on
    // connect - see server.js). Each person gets ONLY their own encrypted
    // copy, not everyone else's — smaller payloads, and no reason for
    // anyone to see the byte-size of copies they can't decrypt anyway.
    for (const r of messageDoc.recipients) {
      ioInstance?.to(r.username).emit("new-message", { ...payload, recipientBlob: r });
    }

    res.status(201).json({
      ok: true,
      message: {
        ...payload,
        recipientBlob: messageDoc.recipients.find((r) => r.username === me),
        deliveryStatus: deliveryStatusFor(messageDoc.recipients, me),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not send message." });
  }
});

// Full inbox: every message this user has an encrypted copy of, that they
// haven't deleted for themselves. The client groups these into 1:1 threads
// (by recipientUsername/senderUsername) or group threads (by groupId), and
// decrypts each using the copy matching their own username.
router.get("/inbox", requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const messages = await Message.find({
      "recipients.username": me,
      deletedFor: { $ne: me },
    })
      .sort({ createdAt: 1 })
      .limit(3000)
      .lean();

    res.json({
      messages: messages.map((m) => ({
        id: m._id,
        senderUsername: m.senderUsername,
        recipientUsername: m.recipientUsername,
        groupId: m.groupId,
        recipientBlob: m.recipients.find((r) => r.username === me),
        deliveryStatus: deliveryStatusFor(m.recipients, me),
        createdAt: m.createdAt,
      })),
      retentionDays: Message.RETENTION_DAYS,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load messages." });
  }
});

// POST /api/messages/mark-read  body: { ids: [messageId, ...] }
// Marks this user's own copy of each message as read, and notifies the
// sender in real time (if online) so their tick marks update. Only ever
// touches the caller's own recipient entry - nobody can mark a message read
// on someone else's behalf.
router.post("/mark-read", requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.slice(0, 200) : [];
    if (ids.length === 0) return res.json({ ok: true, updated: [] });

    const messages = await Message.find({ _id: { $in: ids }, "recipients.username": me });
    const updated = [];

    for (const message of messages) {
      const mine = message.recipients.find((r) => r.username === me);
      if (mine && !mine.read) {
        mine.read = true;
        mine.readAt = new Date();
        await message.save();
        updated.push(String(message._id));
        ioInstance?.to(message.senderUsername).emit("message-read", {
          id: message._id,
          byUsername: me,
          deliveryStatus: deliveryStatusFor(message.recipients, message.senderUsername),
        });
      }
    }

    res.json({ ok: true, updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not update read status." });
  }
});

// DELETE /api/messages/:id  body: { scope: "me" | "everyone" }
//   scope=me:        hides it from MY inbox only; nobody else is affected.
//   scope=everyone:  actually erases the document (all copies' ciphertext
//                     included) so nobody can read it again. Any participant
//                     (sender or any recipient) can do this.
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const scope = req.body?.scope === "everyone" ? "everyone" : "me";
    const me = req.user.username;

    const message = await Message.findById(id);
    if (!message) return res.status(404).json({ error: "Message not found." });

    const isParticipant = message.recipients.some((r) => r.username === me);
    if (!isParticipant) return res.status(403).json({ error: "Not your message." });

    if (scope === "everyone") {
      await Message.deleteOne({ _id: id });
      for (const r of message.recipients) {
        ioInstance?.to(r.username).emit("message-deleted", { id, scope: "everyone" });
      }
    } else {
      if (!message.deletedFor.includes(me)) {
        message.deletedFor.push(me);
        await message.save();
      }
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not delete message." });
  }
});

module.exports = { router, attachIO };
