const express = require("express");

const app = express();
app.use(express.json());

function verifyAccessToken(token) {
  if (token !== "valid-access-token") {
    throw new Error("invalid token");
  }
  return { id: "user-123" };
}

function requireBearerToken(req, res, next) {
  const header = req.get("Authorization");

  if (!header || !header.startsWith("Bearer ")) {
    return res.sendStatus(401);
  }

  if (req.cookies && req.cookies.session) {
    return res.status(400).json({ error: "cookie credentials are not accepted" });
  }

  try {
    req.user = verifyAccessToken(header.slice("Bearer ".length));
    return next();
  } catch (_error) {
    return res.sendStatus(401);
  }
}

app.post("/api/profile", requireBearerToken, async (req, res) => {
  await updateProfile(req.user.id, req.body);
  res.sendStatus(204);
});

async function updateProfile(_userId, _profilePatch) {
  return true;
}

module.exports = app;
