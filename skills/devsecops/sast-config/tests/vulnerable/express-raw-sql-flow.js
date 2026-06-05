app.get("/search", async (req, res) => {
  const where = buildWhereClause(req.query.q);
  const rows = await db.raw(`select * from tickets where ${where}`);
  res.json(rows);
});
