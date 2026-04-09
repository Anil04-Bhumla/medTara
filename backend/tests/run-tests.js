const assert = require("node:assert/strict");

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = process.env.JWT_SECRET || "test-jwt-secret";
process.env.AES_SECRET = process.env.AES_SECRET || "test-aes-secret";

const {
  buildAssessment,
  shouldAutoAssess
} = require("../services/threatAnalysisService");
const {
  isValidEmail,
  isStrongPassword,
  sanitizeFilename
} = require("../utils/validation");
const { hasValidFileSignature } = require("../middleware/uploadMiddleware");

function runTest(name, testFn) {
  try {
    testFn();
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}`);
    console.error(error);
    process.exitCode = 1;
  }
}

runTest("SQL injection payloads are marked critical", () => {
  const assessment = buildAssessment({
    eventType: "Manual Threat Check",
    input: "' UNION SELECT * FROM users --"
  });

  assert.equal(assessment.attackType, "Potential SQL Injection");
  assert.equal(assessment.severity, "critical");
  assert.ok(assessment.matchedRules.includes("OWASP-A03-Injection"));
});

runTest("Benign events stay low severity", () => {
  const assessment = buildAssessment({
    eventType: "File Download",
    metadata: { filename: "report.pdf" }
  });

  assert.equal(assessment.severity, "low");
  assert.equal(assessment.attackType, "Benign Activity");
});

runTest("Auto assessment recognizes suspicious access-control events", () => {
  assert.equal(shouldAutoAssess("Unauthorized File Download Attempt", {}), true);
  assert.equal(shouldAutoAssess("Successful Login", { note: "normal activity" }), false);
});

runTest("Validation rejects weak credentials and malformed email", () => {
  assert.equal(isValidEmail("invalid-email"), false);
  assert.equal(isStrongPassword("weakpass"), false);
  assert.equal(isStrongPassword("Strong@123"), true);
});

runTest("Filename sanitization removes unsafe characters", () => {
  assert.equal(sanitizeFilename("../../report?.pdf"), ".._.._report_.pdf");
});

runTest("Upload signature detection accepts valid PDF headers", () => {
  const file = {
    mimetype: "application/pdf",
    buffer: Buffer.concat([Buffer.from("%PDF"), Buffer.from(" test content")])
  };

  assert.equal(hasValidFileSignature(file), true);
});

runTest("Threat assessment recognizes suspicious file uploads", () => {
  const assessment = buildAssessment({
    eventType: "Suspicious File Upload Blocked",
    metadata: { originalName: "report.pdf.exe" }
  });

  assert.equal(assessment.attackType, "Potential Malicious File Upload");
  assert.equal(assessment.severity, "critical");
});
