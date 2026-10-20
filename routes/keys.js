const express = require("express");
const rateLimit = require("express-rate-limit");
const router = express.Router();
const User = require("../models/User");
const { requireAuth } = require("../middleware/authMiddleware");

/**
 * Forward-secrecy key directory.
 *
 * Instead of encrypting every message to someone's permanent key, senders
 * encrypt to a ONE-TIME public key that this server hands out once. The
 * recipient's device deletes the matching private key right after reading the
 * message - so even if that person's password or the server database leaks
 * later, that message can no longer be decrypted. When the one-time pool is
 * empty, senders fall back to a rotating "epoch" key (refreshed about daily,
 * old private keys deleted after 2 days).
 *
 * The server only ever holds PUBLIC keys here.
 */
const ID_REGEX = /^[a-f0-9]{32}$/;
const B64_REGEX = /^[A-Za-z0-9+/]{87}=$/; // raw uncompressed P-256 point = 65 bytes
const POOL_MAX = 100;

const validKey = (k) => k && typeof k.id === "string" && ID_REGEX.test(k.id) && typeof k.publicKey === "string" && B64_REGEX.test(k.publicKey);

// Hard cap on how fast one account can pull other people's one-time keys, so
// nobody can drain someone's pool (they'd just get the epoch key instead).
const claimLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => "claim:" + req.user.username,
  validate: false,
  message: { error: "Too many requests. Slow down." },
});

// GET /api/keys/status -> what the server currently holds for ME
router.get("/status", requireAuth, async (req, res) => {
  try {
    const u = await User.findOne({ username: req.user.username }).select("oneTimeKeys epochKey").lean();
    res.json({
      oneTimeCount: u?.oneTimeKeys?.length || 0,
      epochId: u?.epochKey?.id || null,
      epochCreatedAt: u?.epochKey?.createdAt || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load key status." });
  }
});

// POST /api/keys/upload  body: { epoch?: {id,publicKey}, oneTimeKeys?: [{id,publicKey}], replace?: boolean }
router.post("/upload", requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const { epoch, oneTimeKeys, replace } = req.body || {};
    const update = {};

    if (epoch !== undefined && epoch !== null) {
      if (!validKey(epoch)) return res.status(400).json({ error: "Invalid epoch key." });
      update.$set = { epochKey: { id: epoch.id, publicKey: epoch.publicKey, createdAt: new Date() } };
    }
    if (oneTimeKeys !== undefined) {
      if (!Array.isArray(oneTimeKeys) || oneTimeKeys.length > POOL_MAX || !oneTimeKeys.every(validKey)) {
        return res.status(400).json({ error: "Invalid one-time keys." });
      }
      const fresh = oneTimeKeys.map((k) => ({ id: k.id, publicKey: k.publicKey }));
      if (replace === true) {
        // The device lost its private keys (cleared storage / new install):
        // forget every old public key so nobody encrypts to a dead one.
        update.$set = { ...(update.$set || {}), oneTimeKeys: fresh };
      } else if (fresh.length > 0) {
        update.$push = { oneTimeKeys: { $each: fresh, $slice: -POOL_MAX } };
      }
    }
    if (Object.keys(update).length) await User.updateOne({ username: me }, update);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not store keys." });
  }
});

// POST /api/keys/claim  body: { usernames: [..] }
// -> { keys: [{ username, keyId, publicKey, kind: "otk"|"epoch"|"identity" }] }
router.post("/claim", requireAuth, claimLimiter, async (req, res) => {
  try {
    const me = req.user.username;
    const names = [...new Set((Array.isArray(req.body?.usernames) ? req.body.usernames : [])
      .filter((u) => typeof u === "string").map((u) => u.trim().toLowerCase()))].slice(0, 100);
    if (names.length === 0) return res.status(400).json({ error: "No usernames." });

    const [mine, targets] = await Promise.all([
      User.findOne({ username: me }).select("blocked").lean(),
      User.find({ username: { $in: names } }).select("username publicKey epochKey blocked").lean(),
    ]);
    const iBlocked = new Set(mine?.blocked || []);

    const keys = [];
    for (const t of targets) {
      // Never spend a blocked person's one-time keys (they'd be wasted).
      const blockedPair = iBlocked.has(t.username) || (t.blocked || []).includes(me);
      let otk = null;
      if (!blockedPair && t.username !== me) {
        const before = await User.findOneAndUpdate(
          { username: t.username, "oneTimeKeys.0": { $exists: true } },
          { $pop: { oneTimeKeys: -1 } }, // atomically take the first key: nobody else can get it
          { new: false }
        ).select("oneTimeKeys").lean();
        otk = before?.oneTimeKeys?.[0] || null;
      }
      if (otk) keys.push({ username: t.username, keyId: otk.id, publicKey: otk.publicKey, kind: "otk" });
      else if (t.epochKey?.id) keys.push({ username: t.username, keyId: t.epochKey.id, publicKey: t.epochKey.publicKey, kind: "epoch" });
      else keys.push({ username: t.username, keyId: null, publicKey: t.publicKey, kind: "identity" });
    }
    res.json({ keys });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch keys." });
  }
});

module.exports = router;
