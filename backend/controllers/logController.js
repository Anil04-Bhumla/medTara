const { listSecurityLogs } = require("../data/store");

exports.getLogs = async (req, res) => {
  try {
    const logs = await listSecurityLogs();

    res.json(logs);

  } catch (error) {
    res.status(500).json({
      message: "Error fetching logs"
    });
  }
};
