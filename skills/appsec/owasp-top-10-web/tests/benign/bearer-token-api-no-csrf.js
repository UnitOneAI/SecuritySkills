import express from "express";

const app = express();

function rejectAmbientCredentials(req, res, next) {
  if (req.headers.cookie) {
    return res.status(400).json({ error: "cookies are not accepted" });
  }
  return next();
}

function requireBearerToken(req, res, next) {
  const header = req.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) {
    return res.sendStatus(401);
  }
  req.user = { id: "user-123" };
  return next();
}

app.post("/api/profile", rejectAmbientCredentials, requireBearerToken, express.json(), async (req, res) => {
  res.status(204).end();
});

export { app };
