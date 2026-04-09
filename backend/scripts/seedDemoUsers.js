require("../config/runtime");

const bcrypt = require("bcryptjs");

const connectDB = require("../config/db");
const {
  findUserByEmail,
  createUser,
  updateSeedAssignments
} = require("../data/store");

const demoUsers = [
  {
    name: "Admin User",
    email: "admin@securehealth.local",
    password: "Admin@123",
    role: "admin"
  },
  {
    name: "Doctor User",
    email: "doctor@securehealth.local",
    password: "Doctor@123",
    role: "doctor"
  },
  {
    name: "Patient User",
    email: "patient@securehealth.local",
    password: "Patient@123",
    role: "patient"
  }
];

async function seedDemoUsers() {
  await connectDB();

  const savedUsers = {};

  for (const userData of demoUsers) {
    const existingUser = await findUserByEmail(userData.email);

    if (existingUser) {
      existingUser.name = userData.name;
      existingUser.role = userData.role;
      existingUser.password = await bcrypt.hash(userData.password, 10);
      existingUser.loginAttempts = 0;
      existingUser.lockUntil = null;
      await existingUser.save();
      savedUsers[userData.role] = existingUser;
      console.log(`Updated ${userData.role}: ${userData.email}`);
      continue;
    }

    const createdUser = await createUser({
      ...userData,
      password: await bcrypt.hash(userData.password, 10)
    });
    savedUsers[userData.role] = createdUser;
    console.log(`Created ${userData.role}: ${userData.email}`);
  }

  const patient = savedUsers.patient || await findUserByEmail("patient@securehealth.local");
  const doctor = savedUsers.doctor || await findUserByEmail("doctor@securehealth.local");
  const admin = savedUsers.admin || await findUserByEmail("admin@securehealth.local");

  if (patient && doctor && admin) {
    await updateSeedAssignments({
      patientId: patient._id,
      doctorId: doctor._id,
      adminId: admin._id
    });
  }
}

seedDemoUsers()
  .then(() => {
    console.log("Demo users ready.");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Seed failed:", error);
    process.exit(1);
  });
