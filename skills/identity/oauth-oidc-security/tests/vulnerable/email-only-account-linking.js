// Vulnerable: any provider account with the same email is linked to the local
// user, even if the issuer and subject are unrelated.
async function linkProviderAccount(req, res) {
  const claims = await parseProviderClaims(req.body.id_token);
  const user = await db.users.findByEmail(claims.email);

  await db.externalIdentities.insert({
    userId: user.id,
    provider: req.body.provider,
    email: claims.email,
  });

  res.json({ linked: true });
}
