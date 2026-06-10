const crypto = require("crypto");

const secretsByRoute = {
  "/webhooks/payments": [
    { version: "current", value: process.env.WEBHOOK_SECRET_CURRENT },
    { version: "previous", value: process.env.WEBHOOK_SECRET_PREVIOUS },
  ],
};

function verifyDelivery(route, timestamp, rawBody, signature, nowSeconds) {
  if (Math.abs(nowSeconds - Number(timestamp)) > 300) {
    return { ok: false };
  }

  const signedPayload = Buffer.concat([
    Buffer.from(`${timestamp}.`, "utf8"),
    rawBody,
  ]);

  for (const secret of secretsByRoute[route] || []) {
    if (!secret.value) continue;
    const expected = crypto
      .createHmac("sha256", secret.value)
      .update(signedPayload)
      .digest("hex");

    if (safeEqualHex(signature, expected)) {
      return { ok: true, secretVersion: secret.version };
    }
  }

  return { ok: false };
}

function safeEqualHex(left, right) {
  if (!/^[0-9a-f]+$/i.test(left) || left.length !== right.length) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

module.exports = { verifyDelivery };
