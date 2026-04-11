const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const roleMiddleware = require("../middleware/roleMiddleware");
const { createRateLimiter } = require("../middleware/rateLimitMiddleware");

const {
  getSecurityLogs,
  getThreatAssessments
} = require("../controllers/securityController");
const {
  analyzeThreat,
  analyzeWithAI,
  analyzeSecurityLog,
  previewThreat,
  previewWithAI
} = require("../controllers/threatController");

const securityRateLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000,
  maxRequests: 40,
  keyPrefix: "security"
});

router.get("/logs", authMiddleware, securityRateLimiter, roleMiddleware("admin"), getSecurityLogs);
router.get("/assessments", authMiddleware, securityRateLimiter, roleMiddleware("admin"), getThreatAssessments);
router.post("/analyze", authMiddleware, securityRateLimiter, roleMiddleware("admin"), analyzeThreat);
router.post("/analyze-ai", authMiddleware, securityRateLimiter, roleMiddleware("admin"), analyzeWithAI);
router.post("/preview", authMiddleware, securityRateLimiter, roleMiddleware("admin"), previewThreat);
router.post("/preview-ai", authMiddleware, securityRateLimiter, roleMiddleware("admin"), previewWithAI);
router.post("/logs/:id/analyze", authMiddleware, securityRateLimiter, roleMiddleware("admin"), analyzeSecurityLog);

module.exports = router;
