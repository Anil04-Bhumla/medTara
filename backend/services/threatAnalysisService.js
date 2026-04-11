const { createThreatAssessmentRecord } = require("../data/store");

const SQLI_PATTERNS = [
  /(\bunion\b.*\bselect\b)/i,
  /(\bor\b\s+1=1)/i,
  /(--|#|\/\*)/,
  /(\bdrop\b\s+\btable\b)/i,
  /(\bselect\b.+\bfrom\b)/i
];

const XSS_PATTERNS = [
  /<script\b/i,
  /javascript:/i,
  /onerror\s*=/i,
  /onload\s*=/i,
  /<iframe\b/i
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//,
  /\.\.\\/
];

const SHELL_PATTERNS = [
  /(;|\|\||&&)\s*(cat|ls|rm|wget|curl|bash|sh)\b/i,
  /\$\((.*?)\)/,
  /`[^`]+`/
];

const SUSPICIOUS_UPLOAD_PATTERNS = [
  /\.(php|exe|js|sh|bat|cmd|scr|ps1)$/i,
  /\.(pdf|png|jpe?g)\.(exe|js|sh|bat|cmd|scr|ps1)$/i,
  /macro/i
];

function clampRisk(value) {
  return Math.max(0, Math.min(100, value));
}

function severityFromScore(score) {
  if (score >= 85) {
    return "critical";
  }
  if (score >= 65) {
    return "high";
  }
  if (score >= 35) {
    return "medium";
  }
  return "low";
}

function normalizeText(value) {
  if (!value) {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  return JSON.stringify(value);
}

function normalizeList(value, fallback = []) {
  if (!Array.isArray(value)) {
    return fallback;
  }

  const normalized = value
    .map((item) => String(item || "").trim())
    .filter(Boolean);

  return normalized.length ? normalized : fallback;
}

function normalizeOptionalText(value, fallback = null) {
  const text = String(value || "").trim();
  return text || fallback;
}

function normalizeSeverity(value, fallback) {
  const normalized = String(value || "").trim().toLowerCase();
  return ["low", "medium", "high", "critical"].includes(normalized)
    ? normalized
    : fallback;
}

function normalizeConfidence(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return ["low", "medium", "high"].includes(normalized) ? normalized : null;
}

function normalizeRiskScore(value, fallback) {
  const numeric = Number(value);

  if (!Number.isFinite(numeric)) {
    return fallback;
  }

  return clampRisk(Math.round(numeric));
}

function buildAssessment(event) {
  const text = normalizeText(event.input || event.payload || event.metadata);
  const lowerEventType = (event.eventType || event.action || "generic-event").toLowerCase();
  const matchedRules = [];
  const indicators = [];
  let attackType = "Benign Activity";
  let riskScore = 10;
  let impact = "No immediate malicious pattern was identified.";
  let mitigation = [
    "Continue monitoring the event stream for repeated suspicious activity."
  ];

  if (SQLI_PATTERNS.some((pattern) => pattern.test(text))) {
    matchedRules.push("OWASP-A03-Injection");
    indicators.push("SQL keywords or comment markers detected in user-controlled input");
    attackType = "Potential SQL Injection";
    riskScore = Math.max(riskScore, 85);
    impact = "An attacker may manipulate database queries, exfiltrate records, or alter healthcare data.";
    mitigation = [
      "Use parameterized queries everywhere.",
      "Validate and sanitize user-controlled input.",
      "Log and rate-limit repeated malicious requests from the same source."
    ];
  }

  if (XSS_PATTERNS.some((pattern) => pattern.test(text))) {
    matchedRules.push("OWASP-A03-Cross-Site-Scripting");
    indicators.push("Active script content or event-handler payload detected");
    attackType = attackType === "Benign Activity" ? "Potential Cross-Site Scripting" : attackType;
    riskScore = Math.max(riskScore, 75);
    impact = "An attacker may execute scripts in another user's browser and steal session data.";
    mitigation = [
      "Escape untrusted output before rendering.",
      "Validate and sanitize rich-text or free-form inputs.",
      "Add Content-Security-Policy headers on the frontend server."
    ];
  }

  if (PATH_TRAVERSAL_PATTERNS.some((pattern) => pattern.test(text))) {
    matchedRules.push("OWASP-A01-Broken-Access-Control");
    indicators.push("Path traversal tokens detected");
    attackType = attackType === "Benign Activity" ? "Potential Path Traversal" : attackType;
    riskScore = Math.max(riskScore, 70);
    impact = "An attacker may attempt to access files outside intended storage boundaries.";
    mitigation = [
      "Normalize and validate file paths on the server.",
      "Never trust client-supplied filenames or paths.",
      "Restrict downloads to records tied to the authenticated user or role."
    ];
  }

  if (SHELL_PATTERNS.some((pattern) => pattern.test(text))) {
    matchedRules.push("OWASP-A03-Command-Injection");
    indicators.push("Shell metacharacters or command substitution syntax detected");
    attackType = attackType === "Benign Activity" ? "Potential Command Injection" : attackType;
    riskScore = Math.max(riskScore, 90);
    impact = "An attacker may try to execute arbitrary operating-system commands on the server.";
    mitigation = [
      "Avoid shell execution for user-controlled values.",
      "Use allowlists for accepted command arguments.",
      "Generate an immediate alert for admin review."
    ];
  }

  if (lowerEventType.includes("failed login")) {
    matchedRules.push("Brute-Force-Login");
    indicators.push("Repeated login failures detected");
    attackType = attackType === "Benign Activity" ? "Potential Brute Force Attempt" : attackType;
    riskScore = Math.max(riskScore, 45);
    impact = "Repeated failed logins can indicate credential stuffing or password guessing.";
    mitigation = [
      "Keep account lockout and cooldown logic enabled.",
      "Consider IP-based throttling.",
      "Review whether the username or email is being targeted repeatedly."
    ];
  }

  if (lowerEventType.includes("account locked") || lowerEventType.includes("blocked login")) {
    matchedRules.push("Brute-Force-Lockout");
    indicators.push("Account lockout threshold reached after repeated failed logins");
    attackType = "Brute Force Lockout Triggered";
    riskScore = Math.max(riskScore, 85);
    impact = "A user account has been locked after repeated failed logins, indicating likely brute-force or credential-stuffing activity.";
    mitigation = [
      "Review the source IP and account targeted by the repeated login failures.",
      "Keep the account lockout in place until the cooldown period expires.",
      "Consider notifying the affected user and rotating credentials if needed."
    ];
  }

  if (lowerEventType.includes("unauthorized")) {
    matchedRules.push("OWASP-A01-Broken-Access-Control");
    indicators.push("Unauthorized access attempt recorded");
    attackType = attackType === "Benign Activity" ? "Potential Unauthorized Access Attempt" : attackType;
    riskScore = Math.max(riskScore, 80);
    impact = "The event indicates a user attempted to access protected healthcare resources without permission.";
    mitigation = [
      "Review RBAC decisions for the requested action.",
      "Alert admins when the same user or IP repeats access denials.",
      "Check whether sensitive record ids are being enumerated."
    ];
  }

  if (lowerEventType.includes("suspicious file upload")) {
    matchedRules.push("Malicious-File-Upload");
    indicators.push("Suspicious upload attributes or invalid file signatures detected");
    attackType = "Potential Malicious File Upload";
    riskScore = Math.max(riskScore, 88);
    impact = "An attacker may be attempting to store executable or disguised content on the platform.";
    mitigation = [
      "Block the upload and retain the event for investigation.",
      "Verify MIME type, extension, and file signature before storage.",
      "Review the source account and IP for related malicious behavior."
    ];
  }

  if (SUSPICIOUS_UPLOAD_PATTERNS.some((pattern) => pattern.test(text))) {
    matchedRules.push("Malicious-File-Pattern");
    indicators.push("Suspicious file extension or upload indicator detected");
    attackType = attackType === "Benign Activity" ? "Potential Malicious File Upload" : attackType;
    riskScore = Math.max(riskScore, 82);
    impact = "The event includes file attributes commonly associated with disguised or executable payloads.";
    mitigation = [
      "Reject files with risky double extensions or executable content.",
      "Inspect file signatures instead of trusting names alone.",
      "Escalate repeated attempts for admin review."
    ];
  }

  if (lowerEventType.includes("suspicious")) {
    matchedRules.push("Anomaly-Detection");
    indicators.push("Platform anomaly rule triggered");
    attackType = attackType === "Benign Activity" ? "Suspicious Activity" : attackType;
    riskScore = Math.max(riskScore, 60);
    impact = "The system identified abnormal behavior that warrants review.";
    mitigation = [
      "Review the related logs and user timeline.",
      "Correlate this event with the source IP and recent actions.",
      "Escalate to manual investigation if the behavior repeats."
    ];
  }

  const severity = severityFromScore(riskScore);
  const summary = matchedRules.length
    ? `${attackType} detected with ${severity} severity.`
    : "No strong attack indicator detected; event retained for audit and monitoring.";

  return {
    eventType: event.eventType || event.action || "generic-event",
    summary,
    matchedRules,
    indicators,
    attackType,
    severity,
    riskScore: clampRisk(riskScore),
    impact,
    mitigation,
    rawContext: {
      input: event.input,
      payload: event.payload,
      metadata: event.metadata
    }
  };
}

async function createAssessmentFromEvent(event) {
  const assessment = await buildAssessmentWithAI(event);

  return createThreatAssessmentRecord({
    sourceLog: event.sourceLog || null,
    user: event.user || null,
    ip: event.ip || null,
    ...assessment
  });
}

/**
 * Build the payload sent to the Python AI service.
 * Rule-based output is included only as context/fallback hints.
 */
function buildAIServicePayload(event, ruleBasedAssessment) {
  return {
    eventType: event.eventType || event.action || "generic-event",
    input: normalizeText(event.input),
    payload: normalizeText(event.payload),
    metadata: event.metadata || null,
    ruleBasedHints: {
      summary: ruleBasedAssessment.summary,
      attackType: ruleBasedAssessment.attackType,
      severity: ruleBasedAssessment.severity,
      riskScore: ruleBasedAssessment.riskScore,
      matchedRules: ruleBasedAssessment.matchedRules,
      indicators: ruleBasedAssessment.indicators,
      impact: ruleBasedAssessment.impact,
      mitigation: ruleBasedAssessment.mitigation
    }
  };
}

/**
 * Call the Python AI service for AI-first threat analysis.
 * Returns a complete assessment when AI succeeds, otherwise null.
 */
async function callAIService(event, ruleBasedAssessment) {
  const aiServiceUrl = process.env.AI_SERVICE_URL || "http://localhost:5001";

  try {
    const response = await fetch(`${aiServiceUrl}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildAIServicePayload(event, ruleBasedAssessment)),
      signal: AbortSignal.timeout(30000)
    });

    if (!response.ok) {
      console.error("AI service returned non-OK status:", response.status);
      return null;
    }

    const data = await response.json();

    if (data.success && data.analysis) {
      return data.analysis;
    }

    return null;
  } catch (error) {
    console.error("AI service call failed (graceful fallback):", error.message);
    return null;
  }
}

function mergeAIAssessment(ruleBasedAssessment, aiResult) {
  const primaryMitigation = normalizeList(
    aiResult.mitigation,
    normalizeList(aiResult.aiMitigation, ruleBasedAssessment.mitigation)
  );
  const primaryIndicators = normalizeList(aiResult.indicators, ruleBasedAssessment.indicators);
  const primaryRules = normalizeList(aiResult.matchedRules, ruleBasedAssessment.matchedRules);
  const summary = normalizeOptionalText(
    aiResult.summary,
    normalizeOptionalText(aiResult.aiSummary, ruleBasedAssessment.summary)
  );
  const impact = normalizeOptionalText(
    aiResult.impact,
    normalizeOptionalText(aiResult.aiImpact, ruleBasedAssessment.impact)
  );

  return {
    eventType: ruleBasedAssessment.eventType,
    summary,
    matchedRules: primaryRules,
    indicators: primaryIndicators,
    attackType: normalizeOptionalText(aiResult.attackType, ruleBasedAssessment.attackType),
    severity: normalizeSeverity(aiResult.severity, ruleBasedAssessment.severity),
    riskScore: normalizeRiskScore(aiResult.riskScore, ruleBasedAssessment.riskScore),
    impact,
    mitigation: primaryMitigation,
    rawContext: ruleBasedAssessment.rawContext,
    aiSummary: normalizeOptionalText(aiResult.aiSummary, summary),
    aiImpact: normalizeOptionalText(aiResult.aiImpact, impact),
    aiMitigation: normalizeList(aiResult.aiMitigation, primaryMitigation),
    aiConfidence: normalizeConfidence(aiResult.aiConfidence),
    aiAttackVector: normalizeOptionalText(aiResult.aiAttackVector),
    aiAnalyzed: true
  };
}

/**
 * Build an AI-first assessment and fall back to rule-based analysis if needed.
 */
async function buildAssessmentWithAI(event) {
  const ruleBased = buildAssessment(event);
  const aiResult = await callAIService(event, ruleBased);

  if (aiResult) {
    return mergeAIAssessment(ruleBased, aiResult);
  }

  return { ...ruleBased, aiAnalyzed: false };
}

/**
 * Full pipeline: AI-first analysis, then persist to database.
 */
async function createAssessmentWithAI(event) {
  return createAssessmentFromEvent(event);
}

function shouldAutoAssess(action, metadata) {
  const lowerAction = (action || "").toLowerCase();
  const text = normalizeText(metadata).toLowerCase();

  return [
    "failed login",
    "unauthorized",
    "suspicious"
  ].some((token) => lowerAction.includes(token)) ||
    /script|select|union|drop|javascript:|onerror|iframe|\.\.\//.test(text);
}

module.exports = {
  buildAssessment,
  buildAssessmentWithAI,
  createAssessmentFromEvent,
  createAssessmentWithAI,
  shouldAutoAssess
};
