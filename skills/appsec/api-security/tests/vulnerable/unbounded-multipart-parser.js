// Vulnerable fixture: multipart parser accepts unbounded file arrays.

const express = require("express");
const multer = require("multer");

const app = express();
const upload = multer();

app.post("/api/documents/upload", upload.array("files"), async (req, res) => {
  await Promise.all(req.files.map((file) => processDocument(file.buffer)));
  return res.json({ processed: req.files.length });
});

module.exports = app;

// Expected review outcome: Medium or High when gateway limits are not matched
// by multipart file count, per-file size, total part count, and downstream
// parser/converter resource limits.
