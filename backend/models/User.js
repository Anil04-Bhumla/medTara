const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },

  email: {
    type: String,
    required: true,
    unique: true
  },

  password: {
    type: String,
    required: true
  },

  role: {
    type: String,
    enum: ["patient", "doctor", "admin"],
    default: "patient"
  },

  // 🔐 NEW FIELDS (Add these)
  loginAttempts: {
    type: Number,
    default: 0
  },

  lockUntil: {
    type: Date,
    default: null
  }

}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);