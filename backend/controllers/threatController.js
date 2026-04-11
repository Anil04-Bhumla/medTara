const {
  buildAssessmentWithAI,
  createAssessmentWithAI
} = require("../services/threatAnalysisService");
const { logEvent } = require("../utils/logger");
const {
  findSecurityLogById,
  findLatestThreatAssessmentBySourceLog
} = require("../data/store");

async function runThreatAnalysis(req, res, actionLabel) {
  try {
    const { eventType, input, payload, metadata } = req.body;

    if (!eventType) {
      return res.status(400).json({
        message: "eventType is required"
      });
    }

    const assessment = await createAssessmentWithAI({
      eventType,
      input,
      payload,
      metadata,
      user: req.user?.id || null,
      ip: req.ip
    });

    await logEvent(req.user?.id || null, actionLabel(eventType), req.ip, {
      eventType,
      aiAnalyzed: assessment.aiAnalyzed === true,
      preview: typeof input === "string" ? input.slice(0, 200) : undefined
    });

    return res.status(201).json(assessment);
  } catch (error) {
    console.error("Threat analysis error:", error);
    return res.status(500).json({
      message: "Threat analysis failed"
    });
  }
}

exports.analyzeThreat = async (req, res) => {
  return runThreatAnalysis(req, res, (eventType) => `AI-Driven Threat Analysis Requested: ${eventType}`);
};

exports.analyzeWithAI = async (req, res) => {
  return runThreatAnalysis(req, res, (eventType) => `AI Threat Analysis Requested: ${eventType}`);
};

exports.analyzeSecurityLog = async (req, res) => {
  try {
    const log = await findSecurityLogById(req.params.id);

    if (!log) {
      return res.status(404).json({
        message: "Security log not found"
      });
    }

    const existingAssessment = await findLatestThreatAssessmentBySourceLog(log._id);

    if (existingAssessment && existingAssessment.aiAnalyzed !== false) {
      return res.json(existingAssessment);
    }

    const assessment = await createAssessmentWithAI({
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
  return exports.previewWithAI(req, res);
};

exports.previewWithAI = async (req, res) => {
  try {
    const { eventType, input, payload, metadata } = req.body;

    if (!eventType) {
      return res.status(400).json({
        message: "eventType is required"
      });
    }

    const preview = await buildAssessmentWithAI({
      eventType,
      input,
      payload,
      metadata
    });

    res.json(preview);
  } catch (error) {
    console.error("AI threat preview error:", error);
    res.status(500).json({
      message: "AI threat preview failed"
    });
  }
};
