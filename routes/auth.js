const express = require("express");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const router = express.Router();
const User = require("../models/User");
const { signToken } = require("../utils/token");
const { requireAuth } = require("../middleware/authMiddleware");
const { hashPhone, isHashed } = require("../utils/phone");
const lockout = require("../utils/lockout");

// Server-side is the authoritative check (client-side validation can always
// be bypassed) - requires the +91 country code plus a valid Indian mobile
// number: exactly 10 digits, starting with 6-9.
const PHONE_REGEX = /^\+91[6-9]\d{9}$/;
const USERNAME_REGEX = /^[a-z0-9_]{3,20}$/; // lowercase letters/digits/underscore
const BCRYPT_ROUNDS = 12;
// Compared against when the account doesn't exist, so "no such user" takes as
// long as "wrong password" and timing can't be used to find valid usernames.
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", BCRYPT_ROUNDS);

// Basic brute-force protection: a handful of attempts per IP per window,
// separate limiters so a slow login doesn't block registration and vice versa.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Try again in a few minutes." },
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many accounts created from this network. Try again later." },
});

// The phone number is deliberately NOT part of the public user (or the login
// token): the server keeps only a one-way fingerprint of it (utils/phone.js).
function publicUser(user) {
  return { username: user.username };
}

router.post("/register", registerLimiter, async (req, res) => {
  try {
    const { username, phoneNumber, password, publicKey, encryptedPrivateKey } = req.body || {};

    // People often type "@name" out of habit - the @ is never part of a username.
    const typedUsername = String(username || "").trim().replace(/^@+/, "");
    if (!typedUsername || !USERNAME_REGEX.test(typedUsername.toLowerCase())) {
      return res.status(400).json({
        error: "Username must be 3-20 characters: lowercase letters, numbers, or underscore.",
      });
    }
    if (!phoneNumber || !PHONE_REGEX.test(String(phoneNumber).trim())) {
      return res
        .status(400)
        .json({ error: "Enter a valid 10-digit Indian mobile number." });
    }
    if (!password || String(password).length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters." });
    }
    if (!publicKey || !encryptedPrivateKey?.ciphertext || !encryptedPrivateKey?.iv || !encryptedPrivateKey?.salt) {
      return res.status(400).json({ error: "Missing encryption key material — this looks like a client bug." });
    }

    const cleanUsername = typedUsername.toLowerCase();
    const cleanPhone = String(phoneNumber).trim();

    const phoneKey = await hashPhone(cleanPhone);
    // Also match the plain-text form: accounts created before phone hashing existed.
    const existing = await User.findOne({ $or: [{ username: cleanUsername }, { phoneNumber: phoneKey }, { phoneNumber: cleanPhone }] });
    if (existing) {
      return res.status(409).json({
        error:
          existing.username === cleanUsername
            ? "That username is taken."
            : "An account with that phone number already exists.",
      });
    }

    const passwordHash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);

    const user = await User.create({
      username: cleanUsername,
      phoneNumber: phoneKey, // fingerprint, never the number itself
      passwordHash,
      publicKey,
      encryptedPrivateKey,
    });

    const token = signToken({ username: user.username });
    res.status(201).json({
      ok: true,
      token,
      user: publicUser(user),
      publicKey: user.publicKey,
      encryptedPrivateKey: user.encryptedPrivateKey,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not register. Is MongoDB running?" });
  }
});

router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) {
      return res.status(400).json({ error: "Username/phone number and password are required." });
    }

    const raw = String(identifier).trim();
    const clean = raw.replace(/^@+/, "").toLowerCase();

    // Too many wrong passwords for this account? Refuse before doing any work.
    const lock = await lockout.check(clean, req.ip);
    if (lock.locked) {
      const mins = Math.max(1, Math.ceil(lock.retryAfterSec / 60));
      res.set("Retry-After", String(lock.retryAfterSec));
      return res.status(429).json({ error: `Too many wrong attempts. Try again in ${mins} minute${mins === 1 ? "" : "s"}.` });
    }

    const lookups = [{ username: clean }];
    if (PHONE_REGEX.test(raw)) lookups.push({ phoneNumber: await hashPhone(raw) }, { phoneNumber: raw });
    const user = await User.findOne({ $or: lookups });

    // Same error for "no such user" and "wrong password" - don't reveal which
    // half was wrong, so an attacker can't use this to enumerate accounts.
    const genericError = { error: "Incorrect username/phone number or password." };
    const matches = await bcrypt.compare(String(password), user ? user.passwordHash : DUMMY_HASH);
    if (!user || !matches) {
      await lockout.recordFailure(clean, req.ip);
      return res.status(401).json(genericError);
    }
    await lockout.clear(clean, req.ip);

    // Older accounts still have a readable number: convert it on first login.
    if (user.phoneNumber && !isHashed(user.phoneNumber)) {
      user.phoneNumber = await hashPhone(user.phoneNumber);
      await user.save();
    }

    const token = signToken({ username: user.username });
    res.json({
      ok: true,
      token,
      user: publicUser(user),
      publicKey: user.publicKey,
      encryptedPrivateKey: user.encryptedPrivateKey,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not log in. Is MongoDB running?" });
  }
});

// Lets a session recover its own key material any time — not just right
// after login — e.g. if the browser's session storage was cleared, or the
// user opened a new tab. The client will need the account password again to
// actually unwrap the private key from this; this endpoint only returns the
// encrypted blob, never anything the server could use to decrypt it itself.
router.get("/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: "Account not found." });
    res.json({
      user: publicUser(user),
      publicKey: user.publicKey,
      encryptedPrivateKey: user.encryptedPrivateKey,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load account." });
  }
});

module.exports = router;
