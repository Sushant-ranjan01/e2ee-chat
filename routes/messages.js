const express = require("express");
const router = express.Router();
const Message = require("../models/Message");
const User = require("../models/User");
const { requireAuth } = require("../middleware/authMiddleware");

// io is attached by server.js so we can push real-time delivery to a
// recipient who's currently online, without this route file needing to
// know about the socket server's internals.
let ioInstance = null;
function attachIO(io) {
  ioInstance = io;
}

function validBlob(b) {
  return b && typeof b.ephemeralPublicKey === "string" && typeof b.iv === "string" && typeof b.ciphertext === "string";
}

router.post("/send", requireAuth, async (req, res) => {
  try {
    const { recipientUsername, forRecipient, forSender } = req.body || {};
    if (!recipientUsername || !validBlob(forRecipient) || !validBlob(forSender)) {
      return res.status(400).json({ error: "Missing or malformed message fields." });
    }
    const cleanRecipient = String(recipientUsername).trim().toLowerCase();
    if (cleanRecipient === req.user.username) {
      return res.status(400).json({ error: "Can't message yourself." });
    }

    const recipient = await User.findOne({ username: cleanRecipient }).select("username").lean();
    if (!recipient) return res.status(404).json({ error: "No user with that username." });

    const message = await Message.create({
      senderUsername: req.user.username,
      recipientUsername: cleanRecipient,
      forRecipient,
      forSender,
    });

    const payload = {
      id: message._id,
      senderUsername: message.senderUsername,
      recipientUsername: message.recipientUsername,
      forRecipient: message.forRecipient,
      forSender: message.forSender,
      createdAt: message.createdAt,
    };

    // Real-time push if the recipient is currently connected (their socket
    // joined a room named after their username on connect - see server.js).
    // The server is just forwarding the same ciphertext it already can't
    // read - this doesn't weaken anything, it's the same blob either way.
    ioInstance?.to(cleanRecipient).emit("new-message", payload);

    res.status(201).json({ ok: true, message: payload });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not send message." });
  }
});

// Full inbox: every message involving this user that they haven't deleted
// for themselves. The client groups these into per-contact threads locally,
// and picks forSender vs forRecipient to decrypt depending on which side
// of the message it is.
router.get("/inbox", requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const messages = await Message.find({
      $or: [{ senderUsername: me }, { recipientUsername: me }],
      deletedFor: { $ne: me },
    })
      .sort({ createdAt: 1 })
      .limit(2000)
      .lean();

    res.json({
      messages: messages.map((m) => ({
        id: m._id,
        senderUsername: m.senderUsername,
        recipientUsername: m.recipientUsername,
        forRecipient: m.forRecipient,
        forSender: m.forSender,
        createdAt: m.createdAt,
      })),
      retentionDays: Message.RETENTION_DAYS,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load messages." });
  }
});

// DELETE /api/messages/:id  body: { scope: "me" | "everyone" }
//   scope=me:        hides it from MY inbox only; the other side is unaffected.
//   scope=everyone:  actually erases the document (ciphertext included) so
//                     nobody can read it again. Either sender or recipient
//                     can do this - it's their conversation too.
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const scope = req.body?.scope === "everyone" ? "everyone" : "me";
    const me = req.user.username;

    const message = await Message.findById(id);
    if (!message) return res.status(404).json({ error: "Message not found." });

    const isParticipant = message.senderUsername === me || message.recipientUsername === me;
    if (!isParticipant) return res.status(403).json({ error: "Not your message." });

    if (scope === "everyone") {
      await Message.deleteOne({ _id: id });
      const otherParty = message.senderUsername === me ? message.recipientUsername : message.senderUsername;
      ioInstance?.to(otherParty).emit("message-deleted", { id, scope: "everyone" });
      ioInstance?.to(me).emit("message-deleted", { id, scope: "everyone" });
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
