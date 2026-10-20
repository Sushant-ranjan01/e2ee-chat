const express = require("express");
const router = express.Router();
const User = require("../models/User");
const { requireAuth } = require("../middleware/authMiddleware");
const prefs = require("../utils/prefs");

const USERNAME_QUERY_REGEX = /^[a-z0-9_]{1,20}$/;

// Search by username only - deliberately never returns phone numbers, so
// finding someone to message doesn't expose their phone number to strangers.
router.get("/search", requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().replace(/^@+/, "").toLowerCase();
    if (!q || !USERNAME_QUERY_REGEX.test(q)) {
      return res.json({ users: [] });
    }

    const users = await User.find({
      username: { $regex: "^" + q, $options: "i", $ne: req.user.username },
    })
      .limit(15)
      .select("username publicKey")
      .lean();

    res.json({ users: users.map((u) => ({ username: u.username, publicKey: u.publicKey })) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Search failed." });
  }
});

// ---------- Privacy: blocking + online-status visibility ----------
const cleanName = (v) => String(v || "").trim().replace(/^@+/, "").toLowerCase();

async function privacyOf(me) {
  const u = await User.findOne({ username: me }).select("blocked showOnlineStatus").lean();
  return { blocked: (u?.blocked || []).slice().sort(), showOnlineStatus: u?.showOnlineStatus !== false };
}

router.get("/me/privacy", requireAuth, async (req, res) => {
  try {
    res.json(await privacyOf(req.user.username));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load privacy settings." });
  }
});

// PUT /api/users/me/privacy  body: { showOnlineStatus: boolean }
router.put("/me/privacy", requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    if (typeof req.body?.showOnlineStatus !== "boolean") return res.status(400).json({ error: "Invalid setting." });
    await User.updateOne({ username: me }, { $set: { showOnlineStatus: req.body.showOnlineStatus } });
    const p = await privacyOf(me);
    prefs.set(me, p);
    res.json(p);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not save the setting." });
  }
});

// POST /api/users/block   body: { username }
router.post("/block", requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const target = cleanName(req.body?.username);
    if (!USERNAME_QUERY_REGEX.test(target)) return res.status(400).json({ error: "Enter a valid username." });
    if (target === me) return res.status(400).json({ error: "You can't block yourself." });
    const exists = await User.exists({ username: target });
    if (!exists) return res.status(404).json({ error: "No user with that username." });
    await User.updateOne({ username: me }, { $addToSet: { blocked: target } });
    const p = await privacyOf(me);
    prefs.set(me, p);
    res.json(p);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not block that user." });
  }
});

// POST /api/users/unblock   body: { username }
router.post("/unblock", requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const target = cleanName(req.body?.username);
    await User.updateOne({ username: me }, { $pull: { blocked: target } });
    const p = await privacyOf(me);
    prefs.set(me, p);
    res.json(p);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not unblock." });
  }
});

// Fetch a single user's public key directly by exact username (used when
// starting a new thread from a known username).
router.get("/:username", requireAuth, async (req, res) => {
  try {
    const username = String(req.params.username).trim().replace(/^@+/, "").toLowerCase();
    const user = await User.findOne({ username }).select("username publicKey").lean();
    if (!user) return res.status(404).json({ error: "No user with that username." });
    res.json({ username: user.username, publicKey: user.publicKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Lookup failed." });
  }
});

module.exports = router;
