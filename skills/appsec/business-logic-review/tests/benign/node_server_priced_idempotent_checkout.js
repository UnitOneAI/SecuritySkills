const idempotency = require("./idempotency");
const catalog = require("./catalog");
const payments = require("./payments");
const orders = require("./orders");

async function checkout(req, res) {
  const requestKey = req.header("Idempotency-Key");
  if (!requestKey) {
    return res.status(400).json({ error: "Idempotency-Key required" });
  }

  const priced = await catalog.priceCart(req.user.id, req.body.items, req.body.discountCode);
  const cartFingerprint = await catalog.fingerprint(req.body.items);
  const keyScope = {
    userId: req.user.id,
    requestKey,
    cartFingerprint,
    discountCode: req.body.discountCode || null,
    amount: priced.total,
    currency: priced.currency,
  };

  const existing = await idempotency.find(keyScope);
  if (existing) {
    return res.status(200).json(existing.response);
  }

  const order = await orders.createPriced(req.user.id, priced);
  await idempotency.reserve(keyScope, { orderId: order.id, amount: priced.total, currency: priced.currency });
  await payments.charge(req.user.card, priced.total, priced.currency);
  await orders.markPaid(order.id);
  return res.status(201).json({ orderId: order.id, total: priced.total });
}

module.exports = { checkout };
