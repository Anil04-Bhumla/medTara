const express = require("express");
const {
  registerUser,
  loginUser,
  logoutUser,
  getCurrentUser
} = require("../controllers/authController");
const { createRateLimiter } = require("../middleware/rateLimitMiddleware");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();
const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 20,
  keyPrefix: "auth"
});

router.post("/register", authRateLimiter, registerUser);
router.post("/login", authRateLimiter, loginUser);
router.post("/logout", authMiddleware, logoutUser);
router.get("/me", authMiddleware, getCurrentUser);

module.exports = router;
