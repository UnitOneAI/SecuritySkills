const idempotency = require("./idempotency");
const catalog = require("./catalog");
const payments = require("./payments");
const orders = require("./orders");

async function checkout(req, res) {
  const key = `${req.user.id}:${req.header("Idempotency-Key")}`;
  const existing = await idempotency.find(key);
  if (existing) {
    return res.status(200).json(existing.response);
  }

  const priced = await catalog.priceCart(req.user.id, req.body.items, req.body.discountCode);
  const order = await orders.createPriced(req.user.id, priced);
  await idempotency.reserve(key, { orderId: order.id, amount: priced.total, currency: priced.currency });
  await payments.charge(req.user.card, priced.total, priced.currency);
  await orders.markPaid(order.id);
  return res.status(201).json({ orderId: order.id, total: priced.total });
}

module.exports = { checkout };
