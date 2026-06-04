// Vulnerable: possession of a credential ID is treated as authentication.
// The signature, challenge, origin, RP ID hash, and UV/UP flags are not checked.
async function finishLogin(req, res) {
  const credential = await db.credentials.findById(req.body.credentialId);
  if (!credential) {
    return res.status(401).json({ error: "unknown credential" });
  }

  req.session.userId = credential.userId;
  req.session.passkey = true;
  res.json({ ok: true });
}
