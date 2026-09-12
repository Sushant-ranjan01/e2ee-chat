const express = require("express");
const router = express.Router();
const User = require("../models/User");
const { requireAuth } = require("../middleware/authMiddleware");

const USERNAME_QUERY_REGEX = /^[a-z0-9_]{1,20}$/;

// Search by username only - deliberately never returns phone numbers, so
// finding someone to message doesn't expose their phone number to strangers.
router.get("/search", requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().toLowerCase();
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

// Fetch a single user's public key directly by exact username (used when
// starting a new thread from a known username).
router.get("/:username", requireAuth, async (req, res) => {
  try {
    const username = String(req.params.username).trim().toLowerCase();
    const user = await User.findOne({ username }).select("username publicKey").lean();
    if (!user) return res.status(404).json({ error: "No user with that username." });
    res.json({ username: user.username, publicKey: user.publicKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Lookup failed." });
  }
});

module.exports = router;
