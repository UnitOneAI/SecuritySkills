app.get("/users", async (req, res) => {
  const sql = "SELECT * FROM users WHERE email = '" + req.query.email + "'";
  const rows = await db.query(sql);
  res.json(rows);
});
