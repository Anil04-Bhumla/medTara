const SecurityLog = require("../models/SecurityLog");
const { createAssessmentFromEvent, shouldAutoAssess } = require("../services/threatAnalysisService");

exports.logEvent = async (userId, action, ip, metadata) => {
  try {
    // save normal log
    const log = await SecurityLog.create({
      user: userId || null,
      action,
      ip,
      metadata
    });

    // 🚨 Suspicious Activity Detection
    const recentLogs = await SecurityLog.find({
      user: userId,
      createdAt: {
        $gte: new Date(Date.now() - 60 * 1000) // last 1 minute
      }
    });

    // if too many actions
    if (recentLogs.length >= 5) {
      const suspiciousLog = await SecurityLog.create({
        user: userId,
        action: "🚨 Suspicious Activity Detected",
        ip,
        metadata: {
          reason: "High request volume in a short period",
          recentLogCount: recentLogs.length
        }
      });

      await createAssessmentFromEvent({
        sourceLog: suspiciousLog._id,
        user: userId,
        ip,
        action: suspiciousLog.action,
        metadata: suspiciousLog.metadata
      });
    }

    if (shouldAutoAssess(action, metadata)) {
      await createAssessmentFromEvent({
        sourceLog: log._id,
        user: userId,
        ip,
        action,
        metadata
      });
    }
  } catch (error) {
    console.error("Logger Error:", error);
  }
};
