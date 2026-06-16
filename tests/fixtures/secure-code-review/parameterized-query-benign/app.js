app.get("/users", async (req, res) => {
  const rows = await db.query(
    "SELECT * FROM users WHERE email = ?",
    [req.query.email]
  );
  res.json(rows);
});
