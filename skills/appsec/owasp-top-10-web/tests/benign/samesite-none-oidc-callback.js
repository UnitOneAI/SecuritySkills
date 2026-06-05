const express = require("express");

const app = express();
app.use(express.urlencoded({ extended: false }));

function validateOidcCallback(req, res, next) {
  const expectedState = req.session && req.session.oidcState;
  const expectedNonce = req.session && req.session.oidcNonce;

  if (!expectedState || req.body.state !== expectedState) {
    return res.sendStatus(403);
  }

  if (!expectedNonce || req.body.nonce !== expectedNonce) {
    return res.sendStatus(403);
  }

  return next();
}

app.use((_req, res, next) => {
  res.cookie("session", "opaque-session-id", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
  });
  next();
});

app.post("/auth/oidc/callback", validateOidcCallback, async (req, res) => {
  await establishSession(req.body.code);
  res.redirect("/account");
});

async function establishSession(_authorizationCode) {
  return true;
}

module.exports = app;
