const fs = require("fs");

require("dotenv").config();

const requiredEnv = ["JWT_SECRET", "AES_SECRET"];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    throw new Error(`${key} must be configured in backend/.env`);
  }
}

function isTruthy(value) {
  return String(value || "").toLowerCase() === "true";
}

function isTestMode() {
  return process.env.NODE_ENV === "test";
}

function isFileDbMode() {
  if (isTestMode()) {
    return true;
  }

  return isTruthy(process.env.ALLOW_FILE_DB);
}

function isMongoRequired() {
  return !isFileDbMode();
}

function validateRuntimeConfig() {
  if (isMongoRequired() && !process.env.MONGO_URI) {
    throw new Error("MONGO_URI must be configured unless ALLOW_FILE_DB=true or NODE_ENV=test");
  }

  if (isTruthy(process.env.HTTPS_ENABLED)) {
    for (const key of ["SSL_KEY_PATH", "SSL_CERT_PATH"]) {
      if (!process.env[key]) {
        throw new Error(`${key} must be configured when HTTPS_ENABLED=true`);
      }

      if (!fs.existsSync(process.env[key])) {
        throw new Error(`${key} points to a missing file: ${process.env[key]}`);
      }
    }
  }
}

validateRuntimeConfig();

module.exports = {
  isFileDbMode,
  isMongoRequired,
  isTestMode,
  isHttpsEnabled: () => isTruthy(process.env.HTTPS_ENABLED)
};
