// Benign: registration is verified against server-side challenge state,
// configured origin/RP ID, and the authenticated enrollment user.
async function registerPasskey(req, res) {
  const enrollment = await db.passkeyEnrollments.consume(req.session.enrollmentId);

  const result = await verifyRegistrationResponse({
    response: req.body.attestation,
    expectedChallenge: enrollment.challenge,
    expectedOrigin: config.webauthn.allowedOrigins,
    expectedRPID: config.webauthn.rpId,
    requireUserVerification: true,
  });

  if (!result.verified) {
    return res.status(400).json({ error: "registration verification failed" });
  }

  const credential = result.registrationInfo.credential;
  await db.credentials.insert({
    userId: req.user.id,
    credentialId: credential.id,
    publicKey: credential.publicKey,
    signCount: credential.counter,
    backupEligible: result.registrationInfo.credentialBackedUp !== undefined,
  });

  res.json({ ok: true });
}
