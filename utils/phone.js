/**
 * phone.js — phone numbers are never stored in readable form.
 *
 * We only need a phone number for two things: "is this number already
 * registered?" and "log in with my number". Both work with a one-way,
 * deterministic fingerprint, so that's all the database keeps.
 *
 * scrypt (deliberately slow + memory-hard) with a secret "pepper" that lives
 * in the server's environment, NOT the database. A stolen database dump alone
 * can't be turned back into numbers, and even someone holding the pepper must
 * pay ~0.1 s of CPU+RAM per guess (an Indian mobile number has ~4 billion
 * possibilities, so brute-forcing them all is impractical).
 *
 * Set PHONE_PEPPER in the environment (any long random string). Changing it
 * later would make existing numbers unmatchable, so set it once and keep it.
 */
const crypto = require("crypto");
const { promisify } = require("util");
const { JWT_SECRET } = require("./token");

const scrypt = promisify(crypto.scrypt);

function pepper() {
  return process.env.PHONE_PEPPER || crypto.createHash("sha256").update("phone-pepper|" + JWT_SECRET).digest();
}

const PREFIX = "h:";
const isHashed = (v) => typeof v === "string" && v.startsWith(PREFIX);

/** "+919876543210" -> "h:<64 hex chars>" (stable for the same number + pepper). */
async function hashPhone(phone) {
  const buf = await scrypt(String(phone), pepper(), 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return PREFIX + buf.toString("hex");
}

module.exports = { hashPhone, isHashed, pepper };
