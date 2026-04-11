const mongoose = require("mongoose");

const threatAssessmentSchema = new mongoose.Schema(
  {
    sourceLog: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "SecurityLog",
      default: null
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },
    ip: {
      type: String,
      default: null
    },
    eventType: {
      type: String,
      required: true
    },
    summary: {
      type: String,
      required: true
    },
    matchedRules: {
      type: [String],
      default: []
    },
    indicators: {
      type: [String],
      default: []
    },
    attackType: {
      type: String,
      required: true
    },
    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      required: true
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      required: true
    },
    impact: {
      type: String,
      required: true
    },
    mitigation: {
      type: [String],
      default: []
    },
    status: {
      type: String,
      enum: ["open", "reviewed", "mitigated"],
      default: "open"
    },
    rawContext: {
      type: Object,
      default: undefined
    },
    aiSummary: {
      type: String,
      default: null
    },
    aiImpact: {
      type: String,
      default: null
    },
    aiMitigation: {
      type: [String],
      default: []
    },
    aiConfidence: {
      type: String,
      enum: ["high", "medium", "low", null],
      default: null
    },
    aiAttackVector: {
      type: String,
      default: null
    },
    aiAnalyzed: {
      type: Boolean,
      default: false
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("ThreatAssessment", threatAssessmentSchema);
