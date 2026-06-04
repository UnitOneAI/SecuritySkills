const crypto = require("crypto");

const key = Buffer.from(process.env.DATA_KEY || "0123456789abcdef0123456789abcdef");
const iv = Buffer.alloc(12, 0);

function encryptCustomerNote(note) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(note, "utf8"), cipher.final()]).toString("hex");
}

function issuePasswordResetCode() {
  return Math.random().toString(36).slice(2);
}

module.exports = { encryptCustomerNote, issuePasswordResetCode };
