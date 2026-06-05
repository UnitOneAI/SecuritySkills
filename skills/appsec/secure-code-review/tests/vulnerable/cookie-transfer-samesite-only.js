function cookieSession(req) {
  const sessionId = req.cookies && req.cookies.session;
  if (!sessionId) {
    throw new Error("missing browser-managed session cookie");
  }
  return loadSession(sessionId);
}

async function transferFunds(req) {
  const session = cookieSession(req);
  // Vulnerable: SameSite=Lax is present on the cookie configuration, but this
  // high-value unsafe action has no request-bound CSRF token and no
  // Origin/Referer validation.
  await transfer(session.userId, req.body.toAccount, req.body.amount);
  return { status: 302, location: "/transfer/complete" };
}

function loadSession(_sessionId) {
  return { userId: "user-123", cookieSameSite: "Lax" };
}

async function transfer(_fromUserId, _toAccount, _amount) {
  return true;
}

module.exports = { transferFunds };
