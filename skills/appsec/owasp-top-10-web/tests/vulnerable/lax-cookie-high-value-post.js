const express = require("express");

const app = express();
app.use(express.urlencoded({ extended: false }));

function cookieSession(req, _res, next) {
  req.user = { id: "user-123" };
  next();
}

app.use((_req, res, next) => {
  res.cookie("session", "opaque-session-id", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
  });
  next();
});

app.post("/transfer", cookieSession, async (req, res) => {
  // Vulnerable: high-value cookie-authenticated state change has no CSRF token,
  // Origin/Referer validation, or Fetch Metadata gate. SameSite=Lax is not
  // enough evidence by itself for this money-moving endpoint.
  await transferMoney(req.user.id, req.body.to, Number(req.body.amount));
  res.redirect("/done");
});

async function transferMoney(_fromUserId, _toUserId, _amount) {
  return true;
}

module.exports = app;
