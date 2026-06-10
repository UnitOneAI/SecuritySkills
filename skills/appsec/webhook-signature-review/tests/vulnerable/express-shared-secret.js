const express = require("express");

const app = express();
app.use(express.json());

app.post("/webhooks/deploy", (req, res) => {
  if (req.header("x-webhook-secret") !== process.env.WEBHOOK_SECRET) {
    return res.sendStatus(401);
  }

  deployEnvironment(req.body.environment);
  res.sendStatus(204);
});

function deployEnvironment(environment) {
  return environment;
}
