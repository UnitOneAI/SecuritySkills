async function usersHandler(req, res, dbClient = db) {
  const rows = await dbClient.query("SELECT * FROM users WHERE email = ?", [req.query.email]);
  res.json(rows);
}

app.get("/users", usersHandler);

module.exports = { usersHandler };
