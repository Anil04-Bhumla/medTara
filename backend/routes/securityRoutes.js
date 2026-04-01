const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const roleMiddleware = require("../middleware/roleMiddleware");

const {
  getSecurityLogs,
  getThreatAssessments
} = require("../controllers/securityController");
const {
  analyzeThreat,
  analyzeSecurityLog,
  previewThreat
} = require("../controllers/threatController");

router.get("/logs", authMiddleware, roleMiddleware("admin"), getSecurityLogs);
router.get("/assessments", authMiddleware, roleMiddleware("admin"), getThreatAssessments);
router.post("/analyze", authMiddleware, roleMiddleware("admin"), analyzeThreat);
router.post("/preview", authMiddleware, roleMiddleware("admin"), previewThreat);
router.post("/logs/:id/analyze", authMiddleware, roleMiddleware("admin"), analyzeSecurityLog);

module.exports = router;
