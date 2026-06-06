const express = require("express");

const app = express();
app.use(express.json());

async function markInvoicePaid(invoiceId) {
  console.log(`paid ${invoiceId}`);
}

app.post("/webhooks/payment", async (req, res) => {
  await markInvoicePaid(req.body.invoice_id);
  res.sendStatus(204);
});

module.exports = app;
