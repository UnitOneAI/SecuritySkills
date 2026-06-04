// Vulnerable: ID token claims are decoded but not verified for signature,
// issuer, audience, expiration, nonce, or authorized party.
async function createSessionFromIdToken(req, res) {
  const claims = jwt.decode(req.body.id_token);

  let user = await db.users.findByEmail(claims.email);
  if (!user) {
    user = await db.users.insert({ email: claims.email, name: claims.name });
  }

  req.session.userId = user.id;
  res.json({ ok: true });
}
