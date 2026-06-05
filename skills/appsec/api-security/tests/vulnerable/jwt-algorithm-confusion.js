const jwt = require("jsonwebtoken");

async function authenticate(token) {
  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
  const key = await lookupKey(header.kid);

  // Vulnerable: algorithm and issuer/audience are not fixed by server-side policy.
  return jwt.verify(token, key);
}

async function lookupKey(kid) {
  return keyStore.get(kid);
}
