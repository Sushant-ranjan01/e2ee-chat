const mongoose = require("mongoose");
const { hashPhone, isHashed } = require("../utils/phone");

/** The TTL index is created once with whatever retention was set at the time;
 *  changing MESSAGE_RETENTION_DAYS later needs this explicit update. */
async function syncMessageRetention() {
  try {
    const { RETENTION_SECONDS } = require("../models/Message");
    await mongoose.connection.db.command({
      collMod: "messages",
      index: { keyPattern: { createdAt: 1 }, expireAfterSeconds: RETENTION_SECONDS },
    });
  } catch (err) {
    // 26 = collection doesn't exist yet (fresh install) - nothing to update.
    if (err.code !== 26 && err.codeName !== "NamespaceNotFound" && err.codeName !== "IndexNotFound") {
      console.warn("Could not update message retention:", err.message);
    }
  }
}

/** One-time conversion: replace any readable phone numbers with fingerprints. */
async function hashLegacyPhones() {
  try {
    const User = require("../models/User");
    const legacy = await User.find({ phoneNumber: { $regex: /^\+/ } }).select("_id phoneNumber").lean();
    for (const u of legacy) {
      if (isHashed(u.phoneNumber)) continue;
      await User.updateOne({ _id: u._id }, { $set: { phoneNumber: await hashPhone(u.phoneNumber) } });
    }
    if (legacy.length) console.log(`Converted ${legacy.length} stored phone number(s) to fingerprints.`);
  } catch (err) {
    console.warn("Phone fingerprint migration skipped:", err.message);
  }
}

async function connectDB() {
  const uri = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/e2ee-chat";
  try {
    await mongoose.connect(uri);
    console.log("MongoDB connected.");
    await syncMessageRetention();
    hashLegacyPhones(); // runs in the background
  } catch (err) {
    console.error("MongoDB connection failed:", err.message);
    console.error(
      "Phone/OTP login won't work until MongoDB is reachable. " +
        "Set MONGODB_URI in your .env if you're not running Mongo locally on the default port."
    );
  }
}

module.exports = connectDB;
