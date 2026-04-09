const { listSecurityLogs, listThreatAssessments } = require("../data/store");

exports.getSecurityLogs = async (req, res) => {
  try {

    const logs = await listSecurityLogs();

    res.json(logs);

  } catch (error) {

    res.status(500).json({
      message: "Error fetching logs"
    });

  }
};

exports.getThreatAssessments = async (req, res) => {
  try {
    const assessments = await listThreatAssessments();

    res.json(assessments);
  } catch (error) {
    res.status(500).json({
      message: "Error fetching threat assessments"
    });
  }
};
