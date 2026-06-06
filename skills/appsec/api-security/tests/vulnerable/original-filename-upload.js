// Vulnerable fixture: trusts MIME type and original filename for storage.

const fs = require("fs/promises");
const express = require("express");
const multer = require("multer");

const app = express();
const upload = multer();

app.post("/api/upload", upload.single("file"), async (req, res) => {
  if (req.file.mimetype !== "image/png") {
    return res.status(400).end();
  }

  await fs.writeFile(`/var/www/uploads/${req.file.originalname}`, req.file.buffer);
  return res.json({ url: `/uploads/${req.file.originalname}` });
});

module.exports = app;

// Expected review outcome: High if attacker-controlled filenames/content are
// written under a web-served path while trusting mimetype/originalname.
