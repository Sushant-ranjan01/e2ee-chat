/**
 * prefs.js — in-memory copy of each ONLINE user's privacy settings, so the
 * socket layer (presence, typing, calls, invites) can enforce blocks and the
 * "hide my online status" setting instantly without a database hit per event.
 * The database (models/User.js) stays the source of truth; routes/users.js
 * updates both whenever someone changes a setting.
 */
const User = require("../models/User");

const cache = new Map(); // username -> { showOnlineStatus:boolean, blocked:Set<string> }
let onChange = () => {};

const DEFAULTS = () => ({ showOnlineStatus: true, blocked: new Set() });

async function load(username) {
  if (cache.has(username)) return cache.get(username);
  let entry = DEFAULTS();
  try {
    const u = await User.findOne({ username }).select("blocked showOnlineStatus").lean();
    if (u) entry = { showOnlineStatus: u.showOnlineStatus !== false, blocked: new Set(u.blocked || []) };
  } catch (err) {
    console.error("prefs load failed:", err.message);
  }
  cache.set(username, entry);
  return entry;
}

function get(username) {
  return cache.get(username) || DEFAULTS();
}

function set(username, { showOnlineStatus, blocked }) {
  cache.set(username, {
    showOnlineStatus: showOnlineStatus !== false,
    blocked: new Set(blocked || []),
  });
  onChange(username);
}

/** True if EITHER person has blocked the other. */
function isBlockedEitherWay(a, b) {
  return get(a).blocked.has(b) || get(b).blocked.has(a);
}

/** Can `viewer` see whether `target` is online? */
function canSeeStatus(viewer, target) {
  const t = get(target);
  return t.showOnlineStatus && !isBlockedEitherWay(viewer, target);
}

function setOnChange(fn) {
  onChange = fn;
}

module.exports = { load, get, set, isBlockedEitherWay, canSeeStatus, setOnChange };
