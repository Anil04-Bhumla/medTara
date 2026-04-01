const SecurityLog = require("../models/SecurityLog");

exports.getLogs = async (req, res) => {
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
