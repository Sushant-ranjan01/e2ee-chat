const mongoose = require("mongoose");

async function connectDB() {
  const uri = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/e2ee-chat";
  try {
    await mongoose.connect(uri);
    console.log("MongoDB connected.");
  } catch (err) {
    console.error("MongoDB connection failed:", err.message);
    console.error(
      "Phone/OTP login won't work until MongoDB is reachable. " +
        "Set MONGODB_URI in your .env if you're not running Mongo locally on the default port."
    );
  }
}

module.exports = connectDB;
