// Benign: account linking uses immutable issuer and subject identifiers and
// requires an authenticated local session before adding a new provider.
async function linkProviderAccount(req, res) {
  requireAuthenticatedSession(req);

  const pending = await db.oauthLinking.consume(req.query.state);
  if (pending.userId !== req.user.id) {
    return res.status(400).json({ error: "invalid linking state" });
  }

  const claims = await validateIdToken(req.body.id_token, {
    issuer: pending.issuer,
    audience: config.clientId,
    nonce: pending.nonce,
  });

  await db.externalIdentities.upsert({
    userId: req.user.id,
    issuer: claims.iss,
    subject: claims.sub,
    emailAtLinkTime: claims.email,
  });

  res.json({ linked: true });
}
