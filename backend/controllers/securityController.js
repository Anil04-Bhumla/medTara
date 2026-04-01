const SecurityLog = require("../models/SecurityLog");
const ThreatAssessment = require("../models/ThreatAssessment");

exports.getSecurityLogs = async (req, res) => {
  try {

    const logs = await SecurityLog.find()
      .populate("user", "email")
      .sort({ createdAt: -1 });

    res.json(logs);

  } catch (error) {

    res.status(500).json({
      message: "Error fetching logs"
    });

  }
};

exports.getThreatAssessments = async (req, res) => {
  try {
    const assessments = await ThreatAssessment.find()
      .populate("user", "email role")
      .populate("sourceLog")
      .sort({ createdAt: -1 });

    res.json(assessments);
  } catch (error) {
    res.status(500).json({
      message: "Error fetching threat assessments"
    });
  }
};
