// Vulnerable fixture: public object URL bypasses quarantine and safe headers.

const express = require("express");

const app = express();

app.get("/api/files/:key", async (req, res) => {
  const objectUrl = `https://public-bucket.example.com/uploads/${req.params.key}`;
  return res.json({
    url: objectUrl,
    headers: {
      "Content-Disposition": "inline",
    },
  });
});

module.exports = app;

// Expected review outcome: Medium or High when public object access can bypass
// scan/quarantine state or serve untrusted content inline without nosniff.
