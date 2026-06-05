function requireBearerToken(req) {
  if (req.headers.cookie) {
    throw new Error("cookie authentication is not accepted on this API route");
  }

  const authorization = req.headers.authorization || "";
  if (!authorization.startsWith("Bearer ")) {
    throw new Error("missing bearer token");
  }

  return verifyAccessToken(authorization.slice("Bearer ".length));
}

async function updateProfile(req) {
  const user = requireBearerToken(req);
  await saveProfile(user.id, req.body.displayName);
  return { status: 204 };
}

function verifyAccessToken(_token) {
  return { id: "user-123" };
}

async function saveProfile(_userId, _displayName) {
  return true;
}

module.exports = { updateProfile };
