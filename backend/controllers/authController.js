const { findUserByEmail, createUser } = require("../data/store");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const {
  isValidEmail,
  isStrongPassword,
  isSafeDisplayName
} = require("../utils/validation");
const { logEvent } = require("../utils/logger"); // ⭐ add this
const { isHttpsEnabled } = require("../config/runtime");

const ALLOWED_SELF_REGISTER_ROLES = ["patient", "doctor"];
const AUTH_COOKIE_NAME = "secure_healthcare_token";

function getAuthCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: isHttpsEnabled(),
    maxAge: 24 * 60 * 60 * 1000,
    path: "/"
  };
}

function buildAuthPayload(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role
  };
}

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

    if (!isSafeDisplayName(name)) {
      return res.status(400).json({
        success: false,
        message: "Name must be between 2 and 80 characters"
      });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address"
      });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
      });
    }

    if (!ALLOWED_SELF_REGISTER_ROLES.includes(requestedRole)) {
      return res.status(403).json({
        success: false,
        message: "You cannot self-register with that role"
      });
    }

    const existingUser = await findUserByEmail(normalizedEmail);

    if (existingUser) {
      return res.status(400).json({
        success : false,
        message: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await createUser({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role: requestedRole
    });

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

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address"
      });
    }

    const user = await findUserByEmail(normalizedEmail);

    if (!user) {
      await logEvent(null, "Failed Login - Unknown Email", req.ip, {
        email: normalizedEmail
      });
      return res.status(400).json({
        message: "Invalid credentials"
      });
    }

    // 🔒 Check if account is locked
    if (user.lockUntil && new Date(user.lockUntil).getTime() > Date.now()) {
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
      {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.cookie(AUTH_COOKIE_NAME, token, getAuthCookieOptions());

    return res.json({
      user: buildAuthPayload(user)
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: error.message });
  }
};

exports.logoutUser = async (req, res) => {
  res.clearCookie(AUTH_COOKIE_NAME, {
    httpOnly: true,
    sameSite: "lax",
    secure: isHttpsEnabled(),
    path: "/"
  });

  return res.json({
    message: "Logged out successfully"
  });
};

exports.getCurrentUser = async (req, res) => {
  return res.json({
    user: buildAuthPayload(req.user)
  });
};
