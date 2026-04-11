const jwt = require("jsonwebtoken");

function readCookie(header, name) {
  if (!header) {
    return null;
  }

  const cookies = header.split(";");

  for (const cookie of cookies) {
    const [rawName, ...rawValueParts] = cookie.trim().split("=");
    if (rawName === name) {
      return decodeURIComponent(rawValueParts.join("="));
    }
  }

  return null;
}

module.exports = function (req, res, next) {
  const authHeader = req.header("Authorization");
  const cookieToken = readCookie(req.headers.cookie, "secure_healthcare_token");
  const token = authHeader
    ? authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.trim()
    : cookieToken;

  if (!token) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
};
