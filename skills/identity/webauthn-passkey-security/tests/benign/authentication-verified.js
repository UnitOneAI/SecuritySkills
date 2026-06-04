// Benign: authentication verifies assertion data before creating a session.
async function finishLogin(req, res) {
  const pending = await db.loginChallenges.consume(req.session.loginChallengeId);
  const credential = await db.credentials.findById(req.body.id);

  if (!credential) {
    return res.status(401).json({ error: "unknown credential" });
  }

  const result = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge: pending.challenge,
    expectedOrigin: config.webauthn.allowedOrigins,
    expectedRPID: config.webauthn.rpId,
    credential: {
      id: credential.credentialId,
      publicKey: credential.publicKey,
      counter: credential.signCount,
    },
    requireUserVerification: pending.requireUserVerification,
  });

  if (!result.verified) {
    return res.status(401).json({ error: "passkey verification failed" });
  }

  await db.credentials.updateCounter(credential.id, result.authenticationInfo.newCounter);
  req.session.userId = credential.userId;
  req.session.assurance = pending.requireUserVerification ? "passkey-uv" : "passkey-up";
  res.json({ ok: true });
}
