const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { logEvent } = require("../utils/logger"); // ⭐ add this

const ALLOWED_SELF_REGISTER_ROLES = ["patient", "doctor"];

// =====================
// Register
// =====================
exports.registerUser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const requestedRole = role || "patient";

    if (!ALLOWED_SELF_REGISTER_ROLES.includes(requestedRole)) {
      return res.status(403).json({
        success: false,
        message: "You cannot self-register with that role"
      });
    }

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(400).json({
        success : false,
        message: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role: requestedRole
    });

    await user.save();

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};



// =====================
// Login (UPDATED 🔥)
// =====================
exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      await logEvent(null, "Failed Login - Unknown Email", req.ip, {
        email: normalizedEmail
      });
      return res.status(400).json({
        message: "Invalid credentials"
      });
    }

    // 🔒 Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const retryAfterMinutes = Math.ceil((new Date(user.lockUntil).getTime() - Date.now()) / (60 * 1000));

      await logEvent(user._id, "Blocked Login While Account Locked", req.ip, {
        email: normalizedEmail,
        retryAfterMinutes
      });

      return res.status(403).json({
        message: "Account locked due to multiple failed login attempts. Try again later.",
        retryAfterMinutes
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    // ❌ Wrong password
    if (!isMatch) {
      user.loginAttempts += 1;
      let accountLocked = false;

      // lock after 5 attempts
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 10 * 60 * 1000);
        accountLocked = true;
      }

      await user.save();

      // ⭐ log failed attempt
      await logEvent(user._id, "Failed Login", req.ip, {
        email: normalizedEmail,
        loginAttempts: user.loginAttempts,
        attemptsRemaining: Math.max(0, 5 - user.loginAttempts),
        accountLocked
      });

      if (accountLocked) {
        await logEvent(user._id, "Account Locked After Failed Logins", req.ip, {
          email: normalizedEmail,
          loginAttempts: user.loginAttempts,
          lockUntil: user.lockUntil
        });
      }

      return res.status(accountLocked ? 403 : 400).json({
        message: accountLocked
          ? "Account locked due to multiple failed login attempts. Try again later."
          : "Invalid credentials",
        attemptsRemaining: Math.max(0, 5 - user.loginAttempts),
        accountLocked
      });
    }

    // ✅ Correct password → reset attempts
    user.loginAttempts = 0;
    user.lockUntil = null;

    await user.save();

    // ⭐ log success
    await logEvent(user._id, "Successful Login", req.ip);

    const token = jwt.sign(
      { id: user._id ,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    return res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: error.message });
  }
};
