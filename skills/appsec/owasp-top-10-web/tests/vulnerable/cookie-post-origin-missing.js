import express from "express";

const app = express();

function cookieSession(req, res, next) {
  req.user = { id: "user-123" };
  return next();
}

app.post("/settings/email", cookieSession, express.json(), (req, res) => {
  return res.json({ userId: req.user.id, email: req.body.email });
});

export { app };
