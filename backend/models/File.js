const mongoose = require("mongoose");

const FileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  path: {
    type: String,
    required: true
  },
  mimeType: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true,
    min: 1
  },
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
