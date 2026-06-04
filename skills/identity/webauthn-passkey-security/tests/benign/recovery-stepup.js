// Benign: recovery can restore account access, but passkey-required admin
// actions remain blocked until the user enrolls and verifies a new passkey.
async function completeEmailRecovery(req, res) {
  const token = await db.recoveryTokens.consume(req.body.token);
  const user = await db.users.findById(token.userId);

  await db.audit.insert({ userId: user.id, event: "email_recovery_complete" });
  await db.notifications.send(user.id, "Account recovery completed");

  req.session.userId = user.id;
  req.session.assurance = "recovered";
  req.session.requiresPasskeyEnrollment = true;
  res.redirect("/security/passkeys/enroll");
}

function requireAdminPasskey(req, res, next) {
  if (req.session.assurance !== "passkey-uv") {
    return res.status(403).json({ error: "passkey step-up required" });
  }
  next();
}
