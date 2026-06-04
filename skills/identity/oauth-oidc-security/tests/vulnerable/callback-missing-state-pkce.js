// Vulnerable: the callback exchanges any authorization code and creates a
// session without checking server-side state or binding a PKCE verifier.
async function oauthCallback(req, res) {
  const tokenSet = await oauthClient.callback(config.redirectUri, req.query);
  const profile = await oauthClient.userinfo(tokenSet.access_token);

  req.session.userId = profile.sub;
  req.session.provider = "example-idp";
  res.redirect("/dashboard");
}
