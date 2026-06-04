const crypto = require("crypto");

function encryptCustomerNote(note, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(note, "utf8"), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function issuePasswordResetCode() {
  return crypto.randomBytes(32).toString("base64url");
}

module.exports = { encryptCustomerNote, issuePasswordResetCode };
