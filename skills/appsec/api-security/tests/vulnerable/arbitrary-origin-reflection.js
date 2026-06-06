function arbitraryOriginReflection(req, res, next) {
  const origin = req.get("Origin");
  if (origin) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Access-Control-Allow-Credentials", "true");
    res.set("Access-Control-Allow-Methods", "GET, POST, DELETE");
  }
  next();
}

module.exports = { arbitraryOriginReflection };
