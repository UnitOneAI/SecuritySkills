const crypto = require("crypto");
const express = require("express");

const app = express();
const seenEvents = new Set();

app.post(
  "/webhooks/payments",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const timestamp = req.header("x-provider-timestamp");
    const signature = req.header("x-provider-signature") || "";
    const eventId = req.header("x-provider-event-id");

    if (!isFresh(timestamp, 300) || !eventId || seenEvents.has(eventId)) {
      return res.sendStatus(401);
    }

    const signedPayload = Buffer.concat([
      Buffer.from(`${timestamp}.`, "utf8"),
      req.body,
    ]);
    const expected = crypto
      .createHmac("sha256", process.env.WEBHOOK_SECRET)
      .update(signedPayload)
      .digest("hex");

    if (!safeEqualHex(signature, expected)) {
      return res.sendStatus(401);
    }

    seenEvents.add(eventId);
    const event = JSON.parse(req.body.toString("utf8"));
    markInvoicePaid(event.invoice_id);
    res.sendStatus(204);
  },
);

function isFresh(timestamp, toleranceSeconds) {
  const sentAt = Number(timestamp);
  if (!Number.isFinite(sentAt)) return false;
  return Math.abs(Date.now() / 1000 - sentAt) <= toleranceSeconds;
}

function safeEqualHex(left, right) {
  if (!/^[0-9a-f]+$/i.test(left) || left.length !== right.length) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function markInvoicePaid(invoiceId) {
  return invoiceId;
}
