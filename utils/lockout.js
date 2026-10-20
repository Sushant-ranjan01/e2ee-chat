/**
 * lockout.js — slows down password guessing, per account.
 *
 * Two independent counters (both stored only as keyed hashes, see models/LoginAttempt.js):
 *   "ip"   = this account + this network.  5 wrong passwords -> locked 15 min,
 *            doubling each further 5 wrong tries (up to 24 h). One attacker's
 *            guesses can't lock the real owner out when the owner logs in
 *            from their own network.
 *   "acct" = this account from anywhere.   30 wrong passwords in total (a
 *            distributed guessing attack) -> locked 1 h, doubling.
 * A correct password clears both.
 */
const crypto = require("crypto");
const LoginAttempt = require("../models/LoginAttempt");
const { pepper } = require("./phone");

const DAY = 24 * 60 * 60 * 1000;
const POLICY = {
  ip: { threshold: 5, base: 15 * 60 * 1000 },
  acct: { threshold: 30, base: 60 * 60 * 1000 },
};

const h = (s) => crypto.createHmac("sha256", pepper()).update(s).digest("hex");

function keysFor(identifier, ip) {
  const id = String(identifier || "").trim().replace(/^@+/, "").toLowerCase();
  return { ip: "ip:" + h(id + "|" + (ip || "")), acct: "acct:" + h(id) };
}

/** Returns { locked: false } or { locked: true, retryAfterSec }. */
async function check(identifier, ip) {
  const keys = keysFor(identifier, ip);
  const rows = await LoginAttempt.find({ key: { $in: [keys.ip, keys.acct] } }).lean();
  const now = Date.now();
  let until = 0;
  for (const r of rows) if (r.lockUntil && r.lockUntil.getTime() > now) until = Math.max(until, r.lockUntil.getTime());
  return until ? { locked: true, retryAfterSec: Math.ceil((until - now) / 1000) } : { locked: false };
}

async function recordFailure(identifier, ip) {
  const keys = keysFor(identifier, ip);
  for (const [scope, key] of Object.entries(keys)) {
    const { threshold, base } = POLICY[scope];
    const row = await LoginAttempt.findOneAndUpdate(
      { key },
      { $inc: { count: 1 }, $set: { expiresAt: new Date(Date.now() + DAY) } },
      { upsert: true, new: true }
    );
    if (row.count % threshold === 0) {
      const level = row.count / threshold - 1;
      const ms = Math.min(base * 2 ** level, DAY);
      await LoginAttempt.updateOne({ key }, { $set: { lockUntil: new Date(Date.now() + ms), expiresAt: new Date(Date.now() + ms + DAY) } });
    }
  }
}

async function clear(identifier, ip) {
  const keys = keysFor(identifier, ip);
  await LoginAttempt.deleteMany({ key: { $in: [keys.ip, keys.acct] } });
}

module.exports = { check, recordFailure, clear, POLICY };
