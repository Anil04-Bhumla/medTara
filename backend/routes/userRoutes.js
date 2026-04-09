const express = require("express");
const router = express.Router();
const auth = require("../middleware/authMiddleware");
const roleMiddleware = require("../middleware/roleMiddleware");
const { listUsers } = require("../data/store");

router.get("/profile", auth, (req, res) => {
  res.json({
    message: "Protected profile data",
    userId: req.user.id
  });
});

router.get("/directory", auth, roleMiddleware("doctor", "admin"), async (req, res) => {
  try {
    const query = {};

    if (req.query.role) {
      query.role = req.query.role;
    }

    const users = await listUsers(query.role);

    res.json(users);
  } catch (error) {
    res.status(500).json({
      message: "Unable to fetch user directory"
    });
  }
});

module.exports = router;
