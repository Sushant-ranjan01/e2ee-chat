const mongoose = require("mongoose");

/**
 * Failed-login counters for brute-force protection (see utils/lockout.js).
 * `key` is a keyed hash - it contains no username, phone number or IP address,
 * so a database leak reveals nothing about who tried to log in. Rows delete
 * themselves automatically (TTL on expiresAt).
 */
const schema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  count: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});

module.exports = mongoose.model("LoginAttempt", schema);
