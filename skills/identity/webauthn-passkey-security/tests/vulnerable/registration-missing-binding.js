// Vulnerable: registration verification trusts client-provided account data and
// does not bind the challenge, origin, or RP ID to server-side state.
async function registerPasskey(req, res) {
  const result = await verifyRegistrationResponse({
    response: req.body.attestation,
    expectedChallenge: req.body.challenge,
    expectedOrigin: req.headers.origin,
    expectedRPID: req.hostname,
    requireUserVerification: false,
  });

  if (result.verified) {
    await db.credentials.insert({
      userId: req.body.userId,
      credentialId: result.registrationInfo.credential.id,
      publicKey: result.registrationInfo.credential.publicKey,
    });
  }

  res.json({ ok: result.verified });
}
