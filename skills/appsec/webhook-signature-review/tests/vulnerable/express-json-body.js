const crypto = require("crypto");
const express = require("express");

const app = express();
app.use(express.json());

app.post("/webhooks/payments", (req, res) => {
  const signature = req.header("x-provider-signature");
  const expected = crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (signature !== expected) {
    return res.sendStatus(401);
  }

  markInvoicePaid(req.body.invoice_id);
  res.sendStatus(204);
});

function markInvoicePaid(invoiceId) {
  return invoiceId;
}
