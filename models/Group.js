const mongoose = require("mongoose");

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  members: { type: [String], required: true }, // usernames, lowercase
  createdBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

groupSchema.index({ members: 1 });

module.exports = mongoose.model("Group", groupSchema);
