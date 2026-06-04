// Benign: callback state and PKCE verifier are consumed from server-side login
// transaction state before the code is exchanged.
async function oauthCallback(req, res) {
  const login = await db.oauthLogins.consume(req.query.state);
  if (!login || login.sessionId !== req.session.id) {
    return res.status(400).json({ error: "invalid OAuth state" });
  }

  const tokenSet = await oauthClient.callback(config.redirectUri, req.query, {
    state: login.state,
    code_verifier: login.codeVerifier,
  });

  const claims = await validateIdToken(tokenSet.id_token, {
    issuer: config.issuer,
    audience: config.clientId,
    nonce: login.nonce,
  });

  req.session.userId = await findOrCreateFederatedUser(claims.iss, claims.sub);
  res.redirect("/dashboard");
}
