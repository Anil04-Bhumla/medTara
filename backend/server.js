const express = require("express");
const cors = require("cors");
const fs = require("fs");
const http = require("http");
const https = require("https");
const { isHttpsEnabled } = require("./config/runtime");

const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");


const app = express();

const allowedOrigins = (process.env.CORS_ORIGIN || "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed by CORS"));
  },
  credentials: true
}));

// app.use(cors({
//   origin : "http://localhost:5173",
//   credentials :  true
// }))

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  if (isHttpsEnabled()) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.json({ limit: "250kb" }));

const userRoutes = require("./routes/userRoutes");

app.use("/api/user", userRoutes);

const securityRoutes = require("./routes/securityRoutes");

app.use("/api/security", securityRoutes);

const fileRoutes = require("./routes/fileRoutes");

app.use("/api/file", fileRoutes);

// Routes
app.use("/api/auth", authRoutes);   // ADD THIS LINE

app.get("/", (req, res) => {
  res.send("Secure Healthcare API Running");
});

const PORT = process.env.PORT || 8000;

function createServer() {
  if (!isHttpsEnabled()) {
    return http.createServer(app);
  }

  return https.createServer({
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH)
  }, app);
}

async function startServer() {
  await connectDB();
  const server = createServer();

  server.listen(PORT, () => {
    const protocol = isHttpsEnabled() ? "https" : "http";
    console.log(`Server running on ${protocol}://localhost:${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
