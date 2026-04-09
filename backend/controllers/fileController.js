const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { encryptFile, decryptFile } = require("../utils/encryption");
const { logEvent } = require("../utils/logger");
const {
  uploadDir,
  hasValidFileSignature,
  detectSuspiciousFilename
} = require("../middleware/uploadMiddleware");
const { sanitizeFilename } = require("../utils/validation");
const {
  findUserByIdAndRole,
  listFilesForUser,
  findFileById,
  createFileRecord
} = require("../data/store");

async function validateAssignmentUsers(patientId, doctorId) {
  let patient = null;
  let doctor = null;

  if (patientId) {
    patient = await findUserByIdAndRole(patientId, "patient");
    if (!patient) {
      throw new Error("Invalid patient selection");
    }
  }

  if (doctorId) {
    doctor = await findUserByIdAndRole(doctorId, "doctor");
    if (!doctor) {
      throw new Error("Invalid doctor selection");
    }
  }

  return { patient, doctor };
}

exports.listFiles = async (req, res) => {
  try {
    const files = await listFilesForUser(req.user);

    res.json(files);
  } catch (error) {
    console.error("List Files Error:", error);
    res.status(500).json({
      message: "Unable to fetch files"
    });
  }
};

exports.updateFileAssignment = async (req, res) => {
  try {
    const file = await findFileById(req.params.id);

    if (!file) {
      return res.status(404).json({
        message: "File not found"
      });
    }

    const { patientId, doctorId } = req.body;
    const { patient, doctor } = await validateAssignmentUsers(patientId, doctorId);

    file.patient = patient ? patient._id : null;
    file.doctor = doctor ? doctor._id : null;
    await file.save();

    await logEvent(req.user.id, "File Assignment Updated", req.ip, {
      fileId: file._id,
      patientId: file.patient,
      doctorId: file.doctor
    });

    const updatedFile = await findFileById(file._id, { populate: true });

    res.json({
      message: "File assignment updated successfully",
      file: updatedFile
    });
  } catch (error) {
    if (error.message === "Invalid patient selection" || error.message === "Invalid doctor selection") {
      return res.status(400).json({
        message: error.message
      });
    }

    console.error("Update Assignment Error:", error);
    res.status(500).json({
      message: "Unable to update file assignment"
    });
  }
};


// =====================
// Upload Multiple Files
// =====================
exports.uploadFile = async (req, res) => {
  try {
    const { patientId, doctorId } = req.body;

    // 🔁 change from req.file → req.files
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        message: "No files uploaded"
      });
    }

    let assignedPatientId = null;
    let assignedDoctorId = null;

    if (patientId || doctorId) {
      const { patient, doctor } = await validateAssignmentUsers(patientId, doctorId);
      assignedPatientId = patient ? patient._id : null;
      if (req.user.role !== "doctor") {
        assignedDoctorId = doctor ? doctor._id : null;
      }
    }

    if (req.user.role === "doctor") {
      assignedDoctorId = req.user.id;
    }

    if (req.user.role === "doctor" && !assignedPatientId) {
      return res.status(400).json({
        message: "Doctors must assign the record to a patient"
      });
    }

    const uploadedFiles = [];

    for (let file of req.files) {
      if (detectSuspiciousFilename(file.originalname) || !hasValidFileSignature(file)) {
        await logEvent(req.user.id, "Suspicious File Upload Blocked", req.ip, {
          originalName: file.originalname,
          mimeType: file.mimetype,
          size: file.size
        });

        return res.status(400).json({
          message: `Suspicious or invalid file detected: ${file.originalname}`
        });
      }

      const encryptedData = encryptFile(file.buffer);
      const safeOriginalName = sanitizeFilename(file.originalname);
      const storedFilename = `${Date.now()}-${crypto.randomUUID()}${path.extname(safeOriginalName)}`;
      const storedPath = path.join(uploadDir, storedFilename);

      fs.writeFileSync(storedPath, encryptedData);

      const newFile = await createFileRecord({
        filename: storedFilename,
        originalName: safeOriginalName,
        path: storedPath,
        mimeType: file.mimetype,
        size: file.size,
        uploadedBy: req.user.id,
        patient: assignedPatientId,
        doctor: assignedDoctorId
      });

      uploadedFiles.push(newFile);
    }

    // 🔐 log event
    await logEvent(req.user.id, "Multiple File Upload", req.ip, {
      patientId: assignedPatientId,
      doctorId: assignedDoctorId,
      fileCount: uploadedFiles.length,
      files: uploadedFiles.map((item) => ({
        id: item._id,
        name: item.originalName,
        size: item.size,
        mimeType: item.mimeType
      }))
    });

    res.json({
      message: "Files uploaded successfully",
      files: uploadedFiles
    });

  } catch (error) {

    console.error("Upload Error:", error);

    res.status(500).json({
      message: "File upload failed"
    });

  }
};



// =====================
// Download File (same)
// =====================
exports.downloadFile = async (req, res) => {
  try {
    const file = await findFileById(req.params.id);

    if (!file) {
      return res.status(404).json({
        message: "File not found"
      });
    }

    const isAdmin = req.user.role === "admin";
    const isUploader = file.uploadedBy && String(file.uploadedBy) === req.user.id;
    const isAssignedPatient = file.patient && String(file.patient) === req.user.id;
    const isAssignedDoctor = file.doctor && String(file.doctor) === req.user.id;

    if (!isAdmin && !isUploader && !isAssignedPatient && !isAssignedDoctor) {
      await logEvent(req.user.id, "Unauthorized File Download Attempt", req.ip, {
        fileId: req.params.id
      });
      return res.status(403).json({
        message: "You are not allowed to access this file"
      });
    }

    const filePath = path.isAbsolute(file.path)
      ? file.path
      : path.join(__dirname, "..", file.path);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        message: "File missing on server"
      });
    }

    const encryptedData = fs.readFileSync(filePath);

    const decryptedData = decryptFile(encryptedData);

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${file.originalName || file.filename}"`
    );
    if (file.mimeType) {
      res.setHeader("Content-Type", file.mimeType);
    }

    await logEvent(req.user.id, "File Download", req.ip, {
      fileId: file._id
    });
    res.send(decryptedData);
  } catch (error) {
    console.error("Download Error:", error);

    res.status(500).json({
      message: "Error downloading file"
    });

  }
};
