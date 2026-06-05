const jwt = require("jsonwebtoken");

const ISSUER = "https://issuer.example.com/";
const AUDIENCE = "api://orders";
const ALGORITHMS = ["RS256"];
const TRUSTED_KIDS = new Set(["orders-2026-01"]);

function authenticate(token) {
  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
  if (!TRUSTED_KIDS.has(header.kid)) throw new Error("unknown kid");
  if (header.jku || header.x5u || header.jwk) throw new Error("untrusted remote key header");

  const publicKey = jwksCache.get(ISSUER, header.kid);
  return jwt.verify(token, publicKey, {
    algorithms: ALGORITHMS,
    issuer: ISSUER,
    audience: AUDIENCE,
    clockTolerance: 30,
  });
}
