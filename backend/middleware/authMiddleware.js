const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  const authHeader = req.header("Authorization");
  const queryToken = typeof req.query.token === "string" ? req.query.token.trim() : "";
  const rawToken = authHeader || queryToken;

  if (!rawToken) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const token = rawToken.startsWith("Bearer ")
      ? rawToken.slice(7).trim()
      : rawToken.trim();

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
};
