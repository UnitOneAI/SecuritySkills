const express = require("express");

const app = express();
app.use(express.json());

function bearerApi(req, res, next) {
  const header = req.get("Authorization");
  if (!header || !header.startsWith("Bearer ")) {
    return res.sendStatus(401);
  }
  return next();
}

app.post("/api/profile", bearerApi, async (_req, res) => {
  res.sendStatus(204);
});

app.post("/auth/refresh", async (req, res) => {
  // Vulnerable: the main API uses explicit bearer headers, but this endpoint
  // rotates tokens from a browser-managed refresh cookie without CSRF/state or
  // Origin/Referer validation.
  const refreshToken = req.cookies && req.cookies.refresh_token;
  if (!refreshToken) {
    return res.sendStatus(401);
  }

  const accessToken = await rotateRefreshToken(refreshToken);
  return res.json({ accessToken });
});

async function rotateRefreshToken(_refreshToken) {
  return "new-access-token";
}

module.exports = app;
