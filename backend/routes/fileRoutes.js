const express = require("express");
const router = express.Router();
const { getLogs } = require("../controllers/logController");
const roleMiddleware = require("../middleware/roleMiddleware");
const upload = require("../middleware/uploadMiddleware");
const authMiddleware = require("../middleware/authMiddleware");

const {
  listFiles,
  uploadFile,
  downloadFile,
  updateFileAssignment
} = require("../controllers/fileController");

router.get("/", authMiddleware, listFiles);
router.patch("/:id/assignment", authMiddleware, roleMiddleware("admin"), updateFileAssignment);

// Upload file
router.post(
    "/upload",
    authMiddleware,
    roleMiddleware("doctor", "admin"), // ✅ added
    upload.array("file", 5),
    uploadFile
  );

  router.get(
    "/logs",
    authMiddleware,
    roleMiddleware("admin"),
    getLogs
  );
// Download file
router.get("/download/:id", authMiddleware, downloadFile);

module.exports = router;
