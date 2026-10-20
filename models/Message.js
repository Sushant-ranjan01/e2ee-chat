const mongoose = require("mongoose");

// Encrypted messages are only kept on the server until delivered. 14 days is
// enough for someone who is offline for a while; everything older is erased
// automatically. (Delivered messages live on each person's own device - keyring.js.)
const RETENTION_DAYS = Number(process.env.MESSAGE_RETENTION_DAYS) || 14;
const RETENTION_SECONDS = RETENTION_DAYS * 24 * 60 * 60;

/**
 * One entry per person who can read this message — for a 1:1 message
 * that's the sender + the recipient (2 entries); for a group message it's
 * every group member (including the sender). Each entry is its own
 * independent ECIES ciphertext (see public/crypto.js), encrypted straight
 * to that person's public key. There is no single "the message" the server
 * could decrypt — only N separately-encrypted copies, each readable by
 * exactly one person's private key.
 *
 * The plaintext each copy decrypts to is a small JSON envelope, e.g.
 * {"type":"text","text":"hi"} or {"type":"file","fileName":...,"dataBase64":...}
 * or {"type":"room-invite","roomCode":"AB12CD"} — see public/messages.js.
 * The server never inspects this; it's opaque ciphertext either way.
 *
 * `read`/`readAt` on each entry power read receipts — set when that
 * specific person's client confirms they've decrypted and displayed the
 * message (POST /api/messages/mark-read). This is metadata about who read
 * what and when, not content, so tracking it doesn't weaken the encryption
 * guarantee at all.
 */
const recipientBlobSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    // Which of the recipient's keys this copy was encrypted to (a one-time or
    // rotating key - see routes/keys.js). null = their long-term identity key
    // (older messages, or recipients on an older app version).
    keyId: { type: String, default: null },
    ephemeralPublicKey: { type: String, required: true },
    iv: { type: String, required: true },
    ciphertext: { type: String, required: true },
    read: { type: Boolean, default: false },
    readAt: { type: Date, default: null },
  },
  { _id: false }
);

const messageSchema = new mongoose.Schema({
  senderUsername: { type: String, required: true, index: true },

  // Exactly one of these is set.
  recipientUsername: { type: String, default: null, index: true }, // 1:1 messages
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: "Group", default: null, index: true },

  recipients: { type: [recipientBlobSchema], required: true },

  // Per-user "delete for me" — hides the message from that user's inbox
  // without affecting anyone else. "Delete for everyone" instead removes
  // the whole document (see routes/messages.js) — the ciphertext is
  // actually gone, not just hidden.
  deletedFor: { type: [String], default: [] },

  createdAt: { type: Date, default: Date.now },
});

messageSchema.index({ "recipients.username": 1, createdAt: 1 });
messageSchema.index({ createdAt: 1 }, { expireAfterSeconds: RETENTION_SECONDS });

module.exports = mongoose.model("Message", messageSchema);
module.exports.RETENTION_DAYS = RETENTION_DAYS;
module.exports.RETENTION_SECONDS = RETENTION_SECONDS;
