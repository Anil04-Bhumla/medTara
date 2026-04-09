const mongoose = require("mongoose");
const { isFileDbMode } = require("./runtime");

const connectDB = async () => {
  if (isFileDbMode()) {
    console.log("Using local file database at backend/data/local-db.json");
    return;
  }

  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000
    });

    console.log("MongoDB Connected");

  } catch (error) {

    console.error("Database connection failed:", error.message);
    process.exit(1);

  }
};

module.exports = connectDB;
