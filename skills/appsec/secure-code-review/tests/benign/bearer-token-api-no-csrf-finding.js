// BENIGN: explicit bearer-token API rejects browser-managed credentials.
// Expected secure-code-review result: do not report missing CSRF token by default.
const express = require("express");
const app = express();

app.use(express.json());

function requireBearerToken(req, res, next) {
  if (req.headers.cookie) {
    return res.status(401).json({ error: "cookie credentials are not accepted" });
  }

  const header = req.get("Authorization");
  if (!header || !header.startsWith("Bearer ")) {
    return res.sendStatus(401);
  }

  req.user = verifyToken(header.slice("Bearer ".length));
  return next();
}

app.post("/api/profile", requireBearerToken, async (req, res) => {
  await updateProfile(req.user.id, req.body);
  res.sendStatus(204);
});

function verifyToken(token) {
  return { id: token.slice(0, 8) || "user-123" };
}

async function updateProfile(_userId, _body) {}
