const mongoose = require("mongoose");

const RETENTION_DAYS = Number(process.env.MESSAGE_RETENTION_DAYS) || 45; // 30-60 day window
const RETENTION_SECONDS = RETENTION_DAYS * 24 * 60 * 60;

/**
 * Every message is encrypted TWICE by the sender's browser before it's ever
 * sent here — once to the recipient's public key (so they can read it) and
 * once to the sender's OWN public key (so the sender can still see their own
 * sent messages later, on this device or any other — without that, a sender
 * couldn't decrypt their own outbox, since the ephemeral key used for the
 * recipient's copy is discarded after sending and the sender never has the
 * recipient's private key). Both are ECIES ciphertexts (see
 * public/crypto.js encryptToPublicKey/decryptFromPublicKey) — this server
 * never has either private key, so it can decrypt neither copy.
 */
const encryptedBlobSchema = new mongoose.Schema(
  {
    ephemeralPublicKey: { type: String, required: true },
    iv: { type: String, required: true },
    ciphertext: { type: String, required: true },
  },
  { _id: false }
);

const messageSchema = new mongoose.Schema({
  senderUsername: { type: String, required: true, index: true },
  recipientUsername: { type: String, required: true, index: true },

  forRecipient: { type: encryptedBlobSchema, required: true },
  forSender: { type: encryptedBlobSchema, required: true },

  // Per-user "delete for me" — hides the message from that user's inbox
  // without affecting the other side. "Delete for everyone" instead removes
  // the whole document (see routes/messages.js), which is stronger: the
  // ciphertext is actually gone, not just hidden.
  deletedFor: { type: [String], default: [] },

  createdAt: { type: Date, default: Date.now },
});

messageSchema.index({ createdAt: 1 }, { expireAfterSeconds: RETENTION_SECONDS });

module.exports = mongoose.model("Message", messageSchema);
module.exports.RETENTION_DAYS = RETENTION_DAYS;
