const fs = require("fs");
const multer = require("multer");
const path = require("path");

const uploadDir = path.join(__dirname, "..", "uploads");
const allowedMimeTypes = new Set([
  "application/pdf",
  "image/jpeg",
  "image/png"
]);

fs.mkdirSync(uploadDir, { recursive: true });

function hasAllowedExtension(filename) {
  const ext = path.extname(filename || "").toLowerCase();
  return [".pdf", ".jpg", ".jpeg", ".png"].includes(ext);
}

function hasValidFileSignature(file) {
  if (!file || !file.buffer) {
    return false;
  }

  const bytes = file.buffer;
  const isPdf = file.mimetype === "application/pdf"
    && bytes.length >= 4
    && bytes.subarray(0, 4).equals(Buffer.from([0x25, 0x50, 0x44, 0x46]));
  const isJpeg = file.mimetype === "image/jpeg"
    && bytes.length >= 3
    && bytes.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]));
  const isPng = file.mimetype === "image/png"
    && bytes.length >= 8
    && bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  return isPdf || isJpeg || isPng;
}

function detectSuspiciousFilename(filename) {
  const normalized = (filename || "").toLowerCase();

  return [
    /\.(php|exe|js|sh|bat|cmd|scr|ps1)(\..+)?$/i,
    /\.(pdf|png|jpe?g)\.(exe|js|sh|bat|cmd|scr|ps1)$/i,
    /[<>:"|?*]/,
    /\.\./
  ].some((pattern) => pattern.test(normalized));
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (!allowedMimeTypes.has(file.mimetype)) {
      return cb(new Error("Only PDF, JPG, and PNG files are allowed"));
    }

    if (!hasAllowedExtension(file.originalname)) {
      return cb(new Error("File extension does not match the allowed upload types"));
    }

    if (detectSuspiciousFilename(file.originalname)) {
      return cb(new Error("Suspicious filename detected"));
    }

    cb(null, true);
  }
});

module.exports = {
  upload,
  uploadDir,
  hasValidFileSignature,
  detectSuspiciousFilename
};
