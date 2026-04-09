function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());
}

function isStrongPassword(password) {
  const value = String(password || "");

  return value.length >= 8
    && /[a-z]/.test(value)
    && /[A-Z]/.test(value)
    && /\d/.test(value)
    && /[^A-Za-z0-9]/.test(value);
}

function isSafeDisplayName(name) {
  const value = String(name || "").trim();
  return value.length >= 2 && value.length <= 80;
}

function sanitizeFilename(filename) {
  return String(filename || "")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 120);
}

module.exports = {
  isValidEmail,
  isStrongPassword,
  isSafeDisplayName,
  sanitizeFilename
};
