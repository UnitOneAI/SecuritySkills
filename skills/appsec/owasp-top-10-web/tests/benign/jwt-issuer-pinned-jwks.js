import { createRemoteJWKSet, jwtVerify } from "jose";

const issuer = "https://login.example.com/";
const audience = "orders-api";
const jwks = createRemoteJWKSet(
  new URL("https://login.example.com/.well-known/jwks.json")
);

export async function authenticateRequest(req) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token) {
    throw new Error("missing token");
  }

  // Expected result: no JWT key-confusion finding. The key source is configured
  // outside the token, issuer and audience are enforced, and kid can only select
  // keys from the trusted issuer's JWKS.
  const result = await jwtVerify(token, jwks, {
    issuer,
    audience,
    algorithms: ["RS256"],
  });

  return result.payload;
}
