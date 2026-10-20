const express = require("express");
const router = express.Router();
const Group = require("../models/Group");
const User = require("../models/User");
const { requireAuth } = require("../middleware/authMiddleware");

const MAX_MEMBERS = 50;

router.post("/", requireAuth, async (req, res) => {
  try {
    const { name, members } = req.body || {};
    const cleanName = String(name || "").trim();
    if (!cleanName) return res.status(400).json({ error: "Group needs a name." });
    if (!Array.isArray(members) || members.length === 0) {
      return res.status(400).json({ error: "Pick at least one other member." });
    }

    const cleanMembers = [...new Set(members.map((m) => String(m).trim().toLowerCase()))];
    const allMembers = [...new Set([...cleanMembers, req.user.username])];
    if (allMembers.length < 2) {
      return res.status(400).json({ error: "Pick at least one other member." });
    }
    if (allMembers.length > MAX_MEMBERS) {
      return res.status(400).json({ error: `Groups are capped at ${MAX_MEMBERS} members.` });
    }

    const found = await User.find({ username: { $in: allMembers } }).select("username").lean();
    const foundUsernames = new Set(found.map((u) => u.username));
    const missing = allMembers.filter((m) => !foundUsernames.has(m));
    if (missing.length > 0) {
      return res.status(400).json({ error: `No such user(s): ${missing.join(", ")}` });
    }

    const group = await Group.create({ name: cleanName, members: allMembers, createdBy: req.user.username });
    res.status(201).json({ ok: true, group: { id: group._id, name: group.name, members: group.members } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not create group." });
  }
});

router.get("/", requireAuth, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user.username }).lean();
    res.json({ groups: groups.map((g) => ({ id: g._id, name: g.name, members: g.members })) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load groups." });
  }
});

// Returns member usernames WITH their public keys, so the client can
// encrypt a message to every member without N separate lookups.
router.get("/:id", requireAuth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id).lean();
    if (!group) return res.status(404).json({ error: "Group not found." });
    if (!group.members.includes(req.user.username)) {
      return res.status(403).json({ error: "Not a member of this group." });
    }

    const users = await User.find({ username: { $in: group.members } }).select("username publicKey").lean();
    res.json({
      id: group._id,
      name: group.name,
      members: users.map((u) => ({ username: u.username, publicKey: u.publicKey })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load group." });
  }
});

module.exports = router;
