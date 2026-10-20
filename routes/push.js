const express = require("express");
const router = express.Router();
const PushToken = require("../models/PushToken");
const { requireAuth } = require("../middleware/authMiddleware");
const { init: initPush } = require("../config/push");

// POST /api/push/register  body: { token }
// Binds this phone's FCM token to the logged-in user (replacing any previous
// user of the same phone).
router.post("/register", requireAuth, async (req, res) => {
  try {
    const token = String(req.body?.token || "");
    if (token.length < 20 || token.length > 4096) return res.status(400).json({ error: "Invalid token." });
    await PushToken.findOneAndUpdate(
      { token },
      { token, username: req.user.username, platform: "android", updatedAt: new Date() },
      { upsert: true, new: true }
    );
    // serverPush tells the app whether the server can really send push (FCM
    // configured). If not, the app keeps using its own local notifications.
    res.json({ ok: true, serverPush: !!initPush() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not register for notifications." });
  }
});

// POST /api/push/unregister  body: { token }   (called on logout)
router.post("/unregister", requireAuth, async (req, res) => {
  try {
    const token = String(req.body?.token || "");
    if (token) await PushToken.deleteOne({ token, username: req.user.username });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not unregister." });
  }
});

module.exports = router;
