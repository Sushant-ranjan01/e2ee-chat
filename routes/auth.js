const express = require("express");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const router = express.Router();
const User = require("../models/User");
const { signToken } = require("../utils/token");
const { requireAuth } = require("../middleware/authMiddleware");

// Server-side is the authoritative check (client-side validation can always
// be bypassed) - requires the +91 country code plus a valid Indian mobile
// number: exactly 10 digits, starting with 6-9.
const PHONE_REGEX = /^\+91[6-9]\d{9}$/;
const USERNAME_REGEX = /^[a-z0-9_]{3,20}$/; // lowercase letters/digits/underscore
const BCRYPT_ROUNDS = 12;

// Usernames are *shown* as "@name" everywhere, so people will naturally type
// the "@" too. It's purely a display prefix: we strip it and store/compare
// the bare name, which keeps every existing account working unchanged.
const stripAt = (s) => String(s || "").trim().replace(/^@+/, "").toLowerCase();

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

function publicUser(user) {
  return { username: user.username, phoneNumber: user.phoneNumber };
}

router.post("/register", registerLimiter, async (req, res) => {
  try {
    const { username, phoneNumber, password, publicKey, encryptedPrivateKey } = req.body || {};

    if (!username || !USERNAME_REGEX.test(stripAt(username))) {
      return res.status(400).json({
        error: "Username must be 3-20 characters: letters, numbers, or underscore (after the @).",
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

    const cleanUsername = stripAt(username);
    const cleanPhone = String(phoneNumber).trim();

    const existing = await User.findOne({ $or: [{ username: cleanUsername }, { phoneNumber: cleanPhone }] });
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
      phoneNumber: cleanPhone,
      passwordHash,
      publicKey,
      encryptedPrivateKey,
    });

    user.lastLoginAt = new Date();
    await user.save();

    const token = signToken({ username: user.username, phoneNumber: user.phoneNumber });
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

    const clean = stripAt(identifier);
    const user = await User.findOne({ $or: [{ username: clean }, { phoneNumber: String(identifier).trim() }] });

    // Same error for "no such user" and "wrong password" - don't reveal which
    // half was wrong, so an attacker can't use this to enumerate accounts.
    const genericError = { error: "Incorrect username/phone number or password." };
    if (!user) return res.status(401).json(genericError);

    const matches = await bcrypt.compare(String(password), user.passwordHash);
    if (!matches) return res.status(401).json(genericError);

    user.lastLoginAt = new Date();
    await user.save();

    const token = signToken({ username: user.username, phoneNumber: user.phoneNumber });
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
