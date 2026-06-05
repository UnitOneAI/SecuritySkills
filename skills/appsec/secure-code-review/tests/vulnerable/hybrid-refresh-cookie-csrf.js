// VULNERABLE: access tokens are bearer-based, but refresh accepts an ambient cookie.
// Expected secure-code-review result: treat refresh as a cookie-authenticated CSRF target.
const express = require("express");
const app = express();

app.post("/api/token/refresh", async (req, res) => {
  const refreshToken = req.cookies && req.cookies.refresh_token;
  if (!refreshToken) {
    return res.sendStatus(401);
  }

  // Missing CSRF token and missing Origin/Referer validation on token rotation.
  const accessToken = await rotateAccessToken(refreshToken);
  res.json({ access_token: accessToken });
});

async function rotateAccessToken(_refreshToken) {
  return "new-access-token";
}
