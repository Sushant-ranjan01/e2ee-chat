const mongoose = require("mongoose");

/**
 * One row per phone (FCM registration token). A token belongs to whichever
 * user logged in last on that phone, so it's unique by token. We store NO
 * message content here - only "this phone can be woken up for this user".
 */
const pushTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  username: { type: String, required: true, index: true, lowercase: true, trim: true },
  platform: { type: String, default: "android" },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("PushToken", pushTokenSchema);
