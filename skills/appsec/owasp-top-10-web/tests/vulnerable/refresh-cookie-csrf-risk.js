import express from "express";

const app = express();

app.post("/auth/refresh", (req, res) => {
  const refreshToken = req.cookies?.refresh_token;
  if (!refreshToken) {
    return res.sendStatus(401);
  }

  return res.json({ accessToken: "new-access-token" });
});

export { app };
