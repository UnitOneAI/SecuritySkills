function getRefreshCookie(req) {
  const token = req.cookies && req.cookies.refresh_token;
  if (!token) {
    throw new Error("missing browser-managed refresh cookie");
  }
  return token;
}

async function rotateAccessToken(req) {
  const refreshToken = getRefreshCookie(req);
  // Vulnerable: the main API uses bearer access tokens, but token rotation
  // still accepts an ambient HttpOnly refresh cookie without CSRF state,
  // anti-forgery middleware, or Origin/Referer validation.
  const accessToken = await rotate(refreshToken);
  return { access_token: accessToken };
}

async function rotate(_refreshToken) {
  return "new-access-token";
}

module.exports = { rotateAccessToken };
