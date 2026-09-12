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
  phoneNumber: { type: String, required: true, unique: true, index: true, trim: true },
  passwordHash: { type: String, required: true },

  publicKey: { type: String, required: true }, // base64 raw ECDH public key

  // Password-wrapped private key — see utils/token.js / public/crypto.js for the scheme.
  encryptedPrivateKey: {
    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    salt: { type: String, required: true },
  },

  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date, default: null },
});

module.exports = mongoose.model("User", userSchema);
