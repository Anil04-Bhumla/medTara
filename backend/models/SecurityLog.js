const mongoose = require("mongoose");

const securityLogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  action: {
    type: String,
    required: true
  },

  ip: {
    type: String
  },

  metadata: {
    type: Object,
    default: undefined
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("SecurityLog", securityLogSchema);
