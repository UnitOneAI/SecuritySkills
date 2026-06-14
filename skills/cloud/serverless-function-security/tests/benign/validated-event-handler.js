export async function handler(event) {
  if (event.version !== "2.0" || !event.requestContext?.authorizer) {
    return { statusCode: 401, body: "unauthorized" };
  }

  const body = JSON.parse(event.body || "{}");
  if (typeof body.customerId !== "string" || typeof body.amount !== "number") {
    return { statusCode: 400, body: "invalid request" };
  }

  await chargeCustomer(body.customerId, body.amount);
  return { statusCode: 204 };
}

async function chargeCustomer(customerId, amount) {
  return { customerId, amount };
}
