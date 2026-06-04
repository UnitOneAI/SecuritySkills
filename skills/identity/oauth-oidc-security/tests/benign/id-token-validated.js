// Benign: ID token validation pins issuer, audience, nonce, signature
// algorithms, and JWKS source before claims are used.
async function validateIdToken(idToken, expected) {
  const jwks = createRemoteJWKSet(new URL(config.jwksUri));
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: expected.issuer,
    audience: expected.audience,
    algorithms: ["RS256", "ES256"],
    clockTolerance: "60s",
  });

  if (payload.nonce !== expected.nonce) {
    throw new Error("invalid OIDC nonce");
  }

  return payload;
}
