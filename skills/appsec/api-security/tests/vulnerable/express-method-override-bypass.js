const express = require("express");
const app = express();

function authorizeOriginalRequest(req, res, next) {
  if (req.method === "POST" && req.path.startsWith("/api/users/")) {
    return next();
  }
  if (req.user && req.user.role === "admin") {
    return next();
  }
  return res.status(403).end();
}

function methodOverrideAfterAuthorization(req, res, next) {
  const override = req.get("X-HTTP-Method-Override");
  if (override) {
    req.method = override.toUpperCase();
  }
  next();
}

app.use(authorizeOriginalRequest);
app.use(methodOverrideAfterAuthorization);

app.delete("/api/users/:id", (req, res) => {
  res.json({ deleted: req.params.id });
});

module.exports = { app, authorizeOriginalRequest, methodOverrideAfterAuthorization };
