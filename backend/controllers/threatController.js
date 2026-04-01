const SecurityLog = require("../models/SecurityLog");
const ThreatAssessment = require("../models/ThreatAssessment");
const {
  buildAssessment,
  createAssessmentFromEvent
} = require("../services/threatAnalysisService");
const { logEvent } = require("../utils/logger");

exports.analyzeThreat = async (req, res) => {
  try {
    const { eventType, input, payload, metadata } = req.body;

    if (!eventType) {
      return res.status(400).json({
        message: "eventType is required"
      });
    }

    const assessment = await createAssessmentFromEvent({
      eventType,
      input,
      payload,
      metadata,
      user: req.user?.id || null,
      ip: req.ip
    });

    await logEvent(req.user?.id || null, `Threat Analysis Requested: ${eventType}`, req.ip, {
      eventType,
      preview: typeof input === "string" ? input.slice(0, 200) : undefined
    });

    res.status(201).json(assessment);
  } catch (error) {
    console.error("Threat analysis error:", error);
    res.status(500).json({
      message: "Threat analysis failed"
    });
  }
};

exports.analyzeSecurityLog = async (req, res) => {
  try {
    const log = await SecurityLog.findById(req.params.id);

    if (!log) {
      return res.status(404).json({
        message: "Security log not found"
      });
    }

    const existingAssessment = await ThreatAssessment.findOne({
      sourceLog: log._id
    }).sort({ createdAt: -1 });

    if (existingAssessment) {
      return res.json(existingAssessment);
    }

    const assessment = await createAssessmentFromEvent({
      sourceLog: log._id,
      user: log.user,
      ip: log.ip,
      action: log.action,
      metadata: log.metadata
    });

    res.status(201).json(assessment);
  } catch (error) {
    console.error("Security log analysis error:", error);
    res.status(500).json({
      message: "Security log analysis failed"
    });
  }
};

exports.previewThreat = (req, res) => {
  try {
    const { eventType, input, payload, metadata } = req.body;

    if (!eventType) {
      return res.status(400).json({
        message: "eventType is required"
      });
    }

    const preview = buildAssessment({
      eventType,
      input,
      payload,
      metadata
    });

    res.json(preview);
  } catch (error) {
    console.error("Threat preview error:", error);
    res.status(500).json({
      message: "Threat preview failed"
    });
  }
};
