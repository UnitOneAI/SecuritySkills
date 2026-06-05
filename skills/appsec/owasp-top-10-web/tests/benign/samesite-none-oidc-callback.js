import express from "express";

const app = express();
const expectedStates = new Set(["state-123"]);

function requireTrustedOrigin(req, res, next) {
  const origin = req.get("Origin");
  if (origin && origin !== "https://idp.example.test") {
    return res.sendStatus(403);
  }
  return next();
}

app.post("/auth/oidc/callback", requireTrustedOrigin, express.urlencoded({ extended: false }), (req, res) => {
  const { state, nonce } = req.body;
  if (!expectedStates.has(state) || typeof nonce !== "string" || nonce.length < 16) {
    return res.sendStatus(400);
  }

  res.cookie("session", "opaque", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  return res.redirect("/dashboard");
});

export { app };
