const express = require("express");

const router = express.Router();

const SecurityLog = require("../models/SecurityLog");

const authMiddleware = require("../middleware/authMiddleware");
const roleMiddleware = require("../middleware/roleMiddleware");

router.get("/logs", authMiddleware, roleMiddleware("admin"), async (req, res) => {

  const logs = await SecurityLog.find().populate("user");

  res.json(logs);

});

module.exports = router;
