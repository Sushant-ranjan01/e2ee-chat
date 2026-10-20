const jwt = require("jsonwebtoken");

const IS_PROD = process.env.NODE_ENV === "production";
const DEV_SECRET = "dev-secret-change-this-before-production";
const JWT_SECRET = process.env.JWT_SECRET || DEV_SECRET;

// Refuse to run in production with a guessable signing secret: anyone who
// knows it can mint a valid login token for ANY account.
if (IS_PROD && (JWT_SECRET === DEV_SECRET || JWT_SECRET.length < 32)) {
  console.error("FATAL: set JWT_SECRET to a random string of 32+ characters (e.g. `openssl rand -hex 32`) when NODE_ENV=production.");
  process.exit(1);
}

// Shorter-lived sessions limit how long a stolen token stays useful.
const TOKEN_TTL = process.env.TOKEN_TTL || "14d";

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

module.exports = { signToken, verifyToken, JWT_SECRET, IS_PROD };
