const allowedOrigins = new Set([
  "https://app.example.test",
  "https://admin.example.test"
]);

function corsExactAllowlist(req, res, next) {
  const origin = req.get("Origin");
  if (allowedOrigins.has(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Access-Control-Allow-Credentials", "true");
    res.set("Vary", "Origin");
  }
  next();
}

module.exports = { corsExactAllowlist };
