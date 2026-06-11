import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from "jose";

export async function authenticateRequest(req) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token) {
    throw new Error("missing token");
  }

  const header = decodeProtectedHeader(token);

  // Expected finding: the verifier trusts a token-supplied jku header to select
  // the JWKS endpoint. An attacker can sign with their own key and point jku at
  // an attacker-controlled JWKS while still using RS256.
  const jwks = createRemoteJWKSet(new URL(header.jku));
  const result = await jwtVerify(token, jwks, {
    algorithms: ["RS256"],
  });

  return result.payload;
}
