const { createAssessmentFromEvent, shouldAutoAssess } = require("../services/threatAnalysisService");
const {
  createSecurityLog,
  countRecentSecurityLogsByUser
} = require("../data/store");

exports.logEvent = async (userId, action, ip, metadata) => {
  try {
    // save normal log
    const log = await createSecurityLog({
      user: userId || null,
      action,
      ip,
      metadata
    });

    // 🚨 Suspicious Activity Detection
    const recentLogs = await countRecentSecurityLogsByUser(userId, 60 * 1000);

    // if too many actions
    if (recentLogs >= 5) {
      const suspiciousLog = await createSecurityLog({
        user: userId,
        action: "🚨 Suspicious Activity Detected",
        ip,
        metadata: {
          reason: "High request volume in a short period",
          recentLogCount: recentLogs
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
