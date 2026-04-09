const express = require("express");
const { registerUser, loginUser } = require("../controllers/authController");
const { createRateLimiter } = require("../middleware/rateLimitMiddleware");

const router = express.Router();
const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 20,
  keyPrefix: "auth"
});

router.post("/register", authRateLimiter, registerUser);
router.post("/login", authRateLimiter, loginUser);

module.exports = router;
