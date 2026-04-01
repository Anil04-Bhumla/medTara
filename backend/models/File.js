const mongoose = require("mongoose");

const FileSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  path: String,
  mimeType: String,
  size: Number,
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },
  doctor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("File", FileSchema);
