const File = require("../models/File");
const User = require("../models/User");
const fs = require("fs");
const path = require("path");

const { encryptFile, decryptFile } = require("../utils/encryption");
const { logEvent } = require("../utils/logger");

async function validateAssignmentUsers(patientId, doctorId) {
  let patient = null;
  let doctor = null;

  if (patientId) {
    patient = await User.findOne({ _id: patientId, role: "patient" });
    if (!patient) {
      throw new Error("Invalid patient selection");
    }
  }

  if (doctorId) {
    doctor = await User.findOne({ _id: doctorId, role: "doctor" });
    if (!doctor) {
      throw new Error("Invalid doctor selection");
    }
  }

  return { patient, doctor };
}

exports.listFiles = async (req, res) => {
  try {
    let query = {};

    if (req.user.role === "doctor") {
      query = {
        $or: [
          { doctor: req.user.id },
          { uploadedBy: req.user.id }
        ]
      };
    } else if (req.user.role === "patient") {
      query = {
        $or: [
          { patient: req.user.id },
          { uploadedBy: req.user.id }
        ]
      };
    }

    const files = await File.find(query)
      .populate("uploadedBy", "name email role")
      .populate("patient", "name email role")
      .populate("doctor", "name email role")
      .sort({ uploadedAt: -1 });

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
    const file = await File.findById(req.params.id);

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

    const updatedFile = await File.findById(file._id)
      .populate("uploadedBy", "name email role")
      .populate("patient", "name email role")
      .populate("doctor", "name email role");

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

      const fileBuffer = fs.readFileSync(file.path);

      const encryptedData = encryptFile(fileBuffer);

      fs.writeFileSync(file.path, encryptedData);

      const newFile = new File({
        filename: file.filename,
        originalName: file.originalname,
        path: file.path,
        mimeType: file.mimetype,
        size: file.size,
        uploadedBy: req.user.id,
        patient: assignedPatientId,
        doctor: assignedDoctorId
      });

      await newFile.save();

      uploadedFiles.push(newFile);
    }

    // 🔐 log event
    await logEvent(req.user.id, "Multiple File Upload", req.ip, {
      patientId: assignedPatientId,
      doctorId: assignedDoctorId
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
    const file = await File.findById(req.params.id);

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
