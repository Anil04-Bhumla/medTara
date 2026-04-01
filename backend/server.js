const express = require("express");
const cors = require("cors");
require("dotenv").config();

const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");


const app = express();


app.use(cors());
app.use(express.json());

const userRoutes = require("./routes/userRoutes");

app.use("/api/user", userRoutes);

const securityRoutes = require("./routes/securityRoutes");

app.use("/api/security", securityRoutes);

const fileRoutes = require("./routes/fileRoutes");

app.use("/api/file", fileRoutes);

// connect database
connectDB();

// Routes
app.use("/api/auth", authRoutes);   // ADD THIS LINE

app.get("/", (req, res) => {
  res.send("Secure Healthcare API Running");
});

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});