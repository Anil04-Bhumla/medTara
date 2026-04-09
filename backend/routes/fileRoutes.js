const express = require("express");

const { getLogs } = require("../controllers/logController");
const roleMiddleware = require("../middleware/roleMiddleware");
const { upload } = require("../middleware/uploadMiddleware");
const authMiddleware = require("../middleware/authMiddleware");
const { createRateLimiter } = require("../middleware/rateLimitMiddleware");
const {
  listFiles,
  uploadFile,
  downloadFile,
  updateFileAssignment
} = require("../controllers/fileController");

const router = express.Router();
const fileRateLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000,
  maxRequests: 60,
  keyPrefix: "file"
});

router.get("/", authMiddleware, fileRateLimiter, listFiles);
router.patch("/:id/assignment", authMiddleware, fileRateLimiter, roleMiddleware("admin"), updateFileAssignment);
router.post(
  "/upload",
  authMiddleware,
  fileRateLimiter,
  roleMiddleware("doctor", "admin"),
  upload.array("file", 5),
  uploadFile
);
router.get("/logs", authMiddleware, fileRateLimiter, roleMiddleware("admin"), getLogs);
router.get("/download/:id", authMiddleware, fileRateLimiter, downloadFile);

module.exports = router;
