const payments = require("./payments");
const orders = require("./orders");

async function checkout(req, res) {
  await payments.charge(req.user.card, req.body.total);
  await orders.create({
    userId: req.user.id,
    items: req.body.items,
    discountCode: req.body.discountCode,
    chargedTotal: req.body.total,
  });
  res.sendStatus(201);
}

module.exports = { checkout };
