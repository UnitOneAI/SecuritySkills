// VULNERABLE: cookie-authenticated high-value action relies on SameSite=Lax only.
// Expected secure-code-review result: report CWE-352.
const express = require("express");
const cookieSession = require("cookie-session");
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(cookieSession({
  name: "session",
  keys: ["example-dev-key"],
  sameSite: "lax",
  httpOnly: true,
  secure: true
}));

app.post("/transfer", async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.sendStatus(401);
  }

  // Missing CSRF token and missing Origin/Referer validation.
  await transferMoney(req.session.userId, req.body.to, req.body.amount);
  res.redirect("/done");
});

async function transferMoney(_fromUserId, _toUserId, _amount) {}
