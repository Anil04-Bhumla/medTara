const crypto = require("crypto");

const algorithm = "aes-256-gcm";
const legacyAlgorithm = "aes-256-cbc";
const encryptionVersion = Buffer.from("ENC1");

function getKey() {
  if (!process.env.AES_SECRET) {
    throw new Error("AES_SECRET is not configured");
  }

  return crypto.scryptSync(process.env.AES_SECRET, "secure-healthcare-platform", 32);
}

exports.encryptFile = (data) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(algorithm, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([
    encryptionVersion,
    iv,
    authTag,
    encrypted
  ]);
};

exports.decryptFile = (data) => {
  if (data.subarray(0, 4).equals(encryptionVersion)) {
    const iv = data.subarray(4, 16);
    const authTag = data.subarray(16, 32);
    const encryptedData = data.subarray(32);
    const decipher = crypto.createDecipheriv(algorithm, getKey(), iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([
      decipher.update(encryptedData),
      decipher.final()
    ]);
  }

  const legacyIv = Buffer.alloc(16, 0);
  const decipher = crypto.createDecipheriv(legacyAlgorithm, getKey(), legacyIv);
  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
};
