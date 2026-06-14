export async function handler(event) {
  console.log("full event", JSON.stringify(event));
  const body = JSON.parse(event.body || "{}");
  await chargeCustomer(body.customerId, body.amount);
  return { statusCode: 204 };
}

async function chargeCustomer(customerId, amount) {
  return { customerId, amount };
}
