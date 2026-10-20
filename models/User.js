const mongoose = require("mongoose");

/**
 * A user's "identity key" is a long-term ECDH keypair used for the async,
 * WhatsApp-style messaging feature (so people can message each other
 * without both being online at once — see routes/messages.js).
 *
 * publicKey is safe to store in plain text — that's the whole point of
 * asymmetric crypto. privateKey is NEVER stored in plain text: the browser
 * encrypts it with a key derived from the user's password (via PBKDF2)
 * before it's ever sent here, and this server only ever holds that
 * encrypted blob. Without the password, this blob is useless — there is no
 * server-side way to recover the private key.
 */
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true, trim: true, lowercase: true },
  // NOT the number itself: a one-way fingerprint ("h:<hex>", see utils/phone.js).
  // Kept in this field so the existing unique index keeps working.
  phoneNumber: { type: String, required: true, unique: true, index: true, trim: true },
  passwordHash: { type: String, required: true },

  publicKey: { type: String, required: true }, // base64 raw ECDH public key

  // Password-wrapped private key — see utils/token.js / public/crypto.js for the scheme.
  encryptedPrivateKey: {
    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    salt: { type: String, required: true },
  },

  // Forward-secrecy key material (see routes/keys.js + public/keyring.js).
  // PUBLIC keys only - the matching private keys live on the person's device
  // and are deleted after use, so a later leak of the identity key/password
  // can't decrypt old messages.
  //   oneTimeKeys: a pool; each is handed to exactly ONE sender, then removed.
  //   epochKey:    fallback used when the pool is empty; rotated about daily.
  oneTimeKeys: { type: [{ _id: false, id: String, publicKey: String }], default: [] },
  epochKey: {
    type: { _id: false, id: String, publicKey: String, createdAt: Date },
    default: null,
  },

  // Privacy controls (see routes/users.js). `blocked` = usernames this person
  // has blocked; showOnlineStatus=false hides their "online" dot from everyone.
  blocked: { type: [String], default: [] },
  showOnlineStatus: { type: Boolean, default: true },

  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date, default: null },
});

module.exports = mongoose.model("User", userSchema);
