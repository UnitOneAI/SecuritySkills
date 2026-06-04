// Vulnerable: email reset silently removes all passkeys and creates a full
// session, bypassing the application's passkey-required admin policy.
async function completeEmailRecovery(req, res) {
  const token = await db.recoveryTokens.consume(req.body.token);
  const user = await db.users.findById(token.userId);

  await db.credentials.deleteMany({ userId: user.id, type: "webauthn" });
  await db.audit.insert({ userId: user.id, event: "email_recovery_complete" });

  req.session.userId = user.id;
  req.session.assurance = "passkey";
  res.redirect("/admin");
}
