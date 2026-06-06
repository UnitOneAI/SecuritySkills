// Vulnerable fixture: download path releases files before scan completion.

const express = require("express");

const app = express();

app.get("/api/files/:id/download", async (req, res) => {
  const file = await files.findById(req.params.id);

  if (!file) {
    return res.status(404).end();
  }

  // The scan status is returned to clients, but it is not enforced before
  // redirecting to the object URL.
  return res.redirect(file.objectUrl);
});

module.exports = app;

// Expected review outcome: High when untrusted files are reachable before a
// clean scan/quarantine release decision is enforced on every download path.
