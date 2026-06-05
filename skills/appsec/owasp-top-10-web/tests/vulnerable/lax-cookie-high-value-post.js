import express from "express";

const app = express();

function cookieSession(req, res, next) {
  req.user = { id: "user-123" };
  return next();
}

app.use((req, res, next) => {
  res.cookie("session", "opaque", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
  return next();
});

app.post("/transfer", cookieSession, express.urlencoded({ extended: false }), async (req, res) => {
  await transferMoney(req.user.id, req.body.to, req.body.amount);
  return res.redirect("/done");
});

async function transferMoney(fromUserId, toAccount, amount) {
  return { fromUserId, toAccount, amount };
}

export { app };
