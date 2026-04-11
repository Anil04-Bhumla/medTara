const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { isFileDbMode } = require("../config/runtime");
const User = require("../models/User");
const File = require("../models/File");
const SecurityLog = require("../models/SecurityLog");
const ThreatAssessment = require("../models/ThreatAssessment");

const dataDir = path.join(__dirname);
const dbFile = path.join(dataDir, "local-db.json");

const initialState = {
  users: [],
  files: [],
  securityLogs: [],
  threatAssessments: []
};

fs.mkdirSync(dataDir, { recursive: true });

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function readState() {
  if (!isFileDbMode()) {
    return clone(initialState);
  }

  if (!fs.existsSync(dbFile)) {
    fs.writeFileSync(dbFile, JSON.stringify(initialState, null, 2));
  }

  return JSON.parse(fs.readFileSync(dbFile, "utf8"));
}

function writeState(state) {
  if (!isFileDbMode()) {
    return;
  }

  fs.writeFileSync(dbFile, JSON.stringify(state, null, 2));
}

function generateId() {
  return crypto.randomUUID().replace(/-/g, "");
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeId(value) {
  if (!value) {
    return null;
  }

  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "object") {
    if (value._id) {
      return String(value._id);
    }
    if (typeof value.toString === "function") {
      return value.toString();
    }
  }

  return String(value);
}

function normalizeDoc(collectionName, doc) {
  return {
    _id: doc._id || generateId(),
    ...clone(doc),
    _collection: collectionName
  };
}

function createSaveableDoc(collectionName, doc) {
  const record = normalizeDoc(collectionName, doc);

  return {
    ...record,
    async save() {
      return saveDoc(collectionName, this);
    }
  };
}

function saveDoc(collectionName, doc) {
  const state = readState();
  const collection = state[collectionName];
  const record = {
    ...clone(doc),
    _id: normalizeId(doc._id) || generateId()
  };

  if ("updatedAt" in record) {
    record.updatedAt = nowIso();
  }

  delete record._collection;
  delete record.save;

  const index = collection.findIndex((item) => item._id === record._id);
  if (index >= 0) {
    collection[index] = record;
  } else {
    collection.push(record);
  }

  writeState(state);
  return createSaveableDoc(collectionName, record);
}

function createDoc(collectionName, doc) {
  return saveDoc(collectionName, {
    ...doc,
    createdAt: doc.createdAt || nowIso(),
    updatedAt: doc.updatedAt || nowIso()
  });
}

function sortByDateDesc(items, field) {
  return [...items].sort((a, b) => new Date(b[field] || 0) - new Date(a[field] || 0));
}

function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    _id: normalizeId(user._id),
    id: normalizeId(user._id),
    name: user.name,
    email: user.email,
    role: user.role
  };
}

function serializeFileDoc(file) {
  if (!file) {
    return null;
  }

  return {
    _id: normalizeId(file._id),
    filename: file.filename,
    originalName: file.originalName,
    path: file.path,
    mimeType: file.mimeType,
    size: file.size,
    uploadedAt: file.uploadedAt,
    uploadedBy: file.uploadedBy && file.uploadedBy.name ? publicUser(file.uploadedBy) : normalizeId(file.uploadedBy),
    patient: file.patient && file.patient.name ? publicUser(file.patient) : normalizeId(file.patient),
    doctor: file.doctor && file.doctor.name ? publicUser(file.doctor) : normalizeId(file.doctor)
  };
}

function serializeSecurityLogDoc(log) {
  if (!log) {
    return null;
  }

  return {
    _id: normalizeId(log._id),
    user: log.user && log.user.name ? publicUser(log.user) : normalizeId(log.user),
    action: log.action,
    ip: log.ip,
    metadata: log.metadata,
    createdAt: log.createdAt
  };
}

function serializeThreatAssessmentDoc(assessment) {
  if (!assessment) {
    return null;
  }

  return {
    _id: normalizeId(assessment._id),
    sourceLog: assessment.sourceLog && assessment.sourceLog.action
      ? serializeSecurityLogDoc(assessment.sourceLog)
      : normalizeId(assessment.sourceLog),
    user: assessment.user && assessment.user.name ? publicUser(assessment.user) : normalizeId(assessment.user),
    ip: assessment.ip,
    eventType: assessment.eventType,
    summary: assessment.summary,
    matchedRules: assessment.matchedRules || [],
    indicators: assessment.indicators || [],
    attackType: assessment.attackType,
    severity: assessment.severity,
    riskScore: assessment.riskScore,
    impact: assessment.impact,
    mitigation: assessment.mitigation || [],
    status: assessment.status,
    rawContext: assessment.rawContext,
    aiSummary: assessment.aiSummary || null,
    aiImpact: assessment.aiImpact || null,
    aiMitigation: assessment.aiMitigation || [],
    aiConfidence: assessment.aiConfidence || null,
    aiAttackVector: assessment.aiAttackVector || null,
    aiAnalyzed: assessment.aiAnalyzed || false,
    createdAt: assessment.createdAt,
    updatedAt: assessment.updatedAt
  };
}

function enrichFile(file, state = readState()) {
  const uploadedBy = state.users.find((user) => user._id === normalizeId(file.uploadedBy));
  const patient = state.users.find((user) => user._id === normalizeId(file.patient));
  const doctor = state.users.find((user) => user._id === normalizeId(file.doctor));

  return {
    ...clone(file),
    uploadedBy: publicUser(uploadedBy) || file.uploadedBy,
    patient: publicUser(patient) || file.patient,
    doctor: publicUser(doctor) || file.doctor
  };
}

function enrichSecurityLog(log, state = readState()) {
  const user = state.users.find((item) => item._id === normalizeId(log.user));

  return {
    ...clone(log),
    user: publicUser(user) || log.user
  };
}

function enrichThreatAssessment(assessment, state = readState()) {
  const user = state.users.find((item) => item._id === normalizeId(assessment.user));
  const sourceLog = state.securityLogs.find((item) => item._id === normalizeId(assessment.sourceLog));

  return {
    ...clone(assessment),
    user: publicUser(user) || assessment.user,
    sourceLog: sourceLog ? enrichSecurityLog(sourceLog, state) : assessment.sourceLog
  };
}

async function findUserByEmail(email) {
  if (isFileDbMode()) {
    const state = readState();
    const user = state.users.find((item) => item.email === email);
    return user ? createSaveableDoc("users", user) : null;
  }

  return User.findOne({ email });
}

async function findUserById(id) {
  if (isFileDbMode()) {
    const state = readState();
    const user = state.users.find((item) => item._id === normalizeId(id));
    return user ? createSaveableDoc("users", user) : null;
  }

  return User.findById(normalizeId(id));
}

async function findUserByIdAndRole(id, role) {
  if (isFileDbMode()) {
    const user = await findUserById(id);
    if (!user || user.role !== role) {
      return null;
    }
    return user;
  }

  return User.findOne({ _id: normalizeId(id), role });
}

async function listUsers(role) {
  if (isFileDbMode()) {
    const state = readState();
    const users = role
      ? state.users.filter((user) => user.role === role)
      : state.users;

    return [...users]
      .sort((a, b) => `${a.role}-${a.name}`.localeCompare(`${b.role}-${b.name}`))
      .map((user) => publicUser(user));
  }

  const query = role ? { role } : {};
  const users = await User.find(query).sort({ role: 1, name: 1 }).lean();
  return users.map((user) => publicUser(user));
}

async function createUser(data) {
  if (isFileDbMode()) {
    return createDoc("users", {
      loginAttempts: 0,
      lockUntil: null,
      ...data
    });
  }

  return User.create({
    loginAttempts: 0,
    lockUntil: null,
    ...data
  });
}

async function listFilesForUser(user) {
  if (isFileDbMode()) {
    const state = readState();
    let files = state.files;

    if (user.role === "doctor") {
      files = files.filter(
        (file) => normalizeId(file.doctor) === user.id || normalizeId(file.uploadedBy) === user.id
      );
    } else if (user.role === "patient") {
      files = files.filter(
        (file) => normalizeId(file.patient) === user.id || normalizeId(file.uploadedBy) === user.id
      );
    }

    return sortByDateDesc(files, "uploadedAt").map((file) => enrichFile(file, state));
  }

  const userId = normalizeId(user.id);
  const query = {};

  if (user.role === "doctor") {
    query.$or = [{ doctor: userId }, { uploadedBy: userId }];
  } else if (user.role === "patient") {
    query.$or = [{ patient: userId }, { uploadedBy: userId }];
  }

  const files = await File.find(query)
    .populate("uploadedBy patient doctor")
    .sort({ uploadedAt: -1 });

  return files.map((file) => serializeFileDoc(file));
}

async function findFileById(id, options = {}) {
  if (isFileDbMode()) {
    const state = readState();
    const file = state.files.find((item) => item._id === normalizeId(id));

    if (!file) {
      return null;
    }

    if (options.populate) {
      return enrichFile(file, state);
    }

    return createSaveableDoc("files", file);
  }

  let query = File.findById(normalizeId(id));

  if (options.populate) {
    query = query.populate("uploadedBy patient doctor");
    const file = await query;
    return serializeFileDoc(file);
  }

  return query;
}

async function createFileRecord(data) {
  if (isFileDbMode()) {
    return createDoc("files", {
      uploadedAt: data.uploadedAt || nowIso(),
      ...data
    });
  }

  return File.create({
    uploadedAt: data.uploadedAt || new Date(),
    ...data
  });
}

async function listSecurityLogs() {
  if (isFileDbMode()) {
    const state = readState();
    return sortByDateDesc(state.securityLogs, "createdAt").map((log) => enrichSecurityLog(log, state));
  }

  const logs = await SecurityLog.find({})
    .populate("user")
    .sort({ createdAt: -1 });

  return logs.map((log) => serializeSecurityLogDoc(log));
}

async function createSecurityLog(data) {
  if (isFileDbMode()) {
    return createDoc("securityLogs", {
      createdAt: nowIso(),
      ...data
    });
  }

  return SecurityLog.create({
    createdAt: new Date(),
    ...data
  });
}

async function countRecentSecurityLogsByUser(userId, windowMs) {
  if (!userId) {
    return 0;
  }

  if (isFileDbMode()) {
    const state = readState();
    const threshold = Date.now() - windowMs;

    return state.securityLogs.filter((log) =>
      normalizeId(log.user) === normalizeId(userId) &&
      new Date(log.createdAt).getTime() >= threshold
    ).length;
  }

  return SecurityLog.countDocuments({
    user: normalizeId(userId),
    createdAt: { $gte: new Date(Date.now() - windowMs) }
  });
}

async function findSecurityLogById(id) {
  if (isFileDbMode()) {
    const state = readState();
    const log = state.securityLogs.find((item) => item._id === normalizeId(id));
    return log ? enrichSecurityLog(log, state) : null;
  }

  const log = await SecurityLog.findById(normalizeId(id)).populate("user");
  return serializeSecurityLogDoc(log);
}

async function listThreatAssessments() {
  if (isFileDbMode()) {
    const state = readState();
    return sortByDateDesc(state.threatAssessments, "createdAt")
      .map((assessment) => enrichThreatAssessment(assessment, state));
  }

  const assessments = await ThreatAssessment.find({})
    .populate("user")
    .populate({
      path: "sourceLog",
      populate: {
        path: "user"
      }
    })
    .sort({ createdAt: -1 });

  return assessments.map((assessment) => serializeThreatAssessmentDoc(assessment));
}

async function findLatestThreatAssessmentBySourceLog(sourceLogId) {
  if (isFileDbMode()) {
    const state = readState();
    const assessments = state.threatAssessments
      .filter((item) => normalizeId(item.sourceLog) === normalizeId(sourceLogId));

    if (!assessments.length) {
      return null;
    }

    return enrichThreatAssessment(sortByDateDesc(assessments, "createdAt")[0], state);
  }

  const assessment = await ThreatAssessment.findOne({ sourceLog: normalizeId(sourceLogId) })
    .populate("user")
    .populate({
      path: "sourceLog",
      populate: {
        path: "user"
      }
    })
    .sort({ createdAt: -1 });

  return serializeThreatAssessmentDoc(assessment);
}

async function createThreatAssessmentRecord(data) {
  if (isFileDbMode()) {
    return createDoc("threatAssessments", {
      createdAt: nowIso(),
      updatedAt: nowIso(),
      status: "open",
      ...data
    });
  }

  return ThreatAssessment.create({
    status: "open",
    ...data
  });
}

async function updateSeedAssignments({ patientId, doctorId, adminId }) {
  if (isFileDbMode()) {
    const state = readState();

    state.files = state.files.map((file) => ({
      ...file,
      patient: file.patient || patientId,
      doctor: file.doctor || doctorId,
      uploadedBy: file.uploadedBy || adminId
    }));

    writeState(state);
    return;
  }

  await File.updateMany(
    {},
    [
      {
        $set: {
          patient: { $ifNull: ["$patient", patientId] },
          doctor: { $ifNull: ["$doctor", doctorId] },
          uploadedBy: { $ifNull: ["$uploadedBy", adminId] }
        }
      }
    ]
  );
}

module.exports = {
  isFileDbMode,
  findUserByEmail,
  findUserById,
  findUserByIdAndRole,
  listUsers,
  createUser,
  saveDoc,
  listFilesForUser,
  findFileById,
  createFileRecord,
  listSecurityLogs,
  createSecurityLog,
  countRecentSecurityLogsByUser,
  findSecurityLogById,
  listThreatAssessments,
  findLatestThreatAssessmentBySourceLog,
  createThreatAssessmentRecord,
  updateSeedAssignments
};
