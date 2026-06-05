app.get("/search", async (req, res) => {
  const q = parseSearchTerm(req.query.q);
  const rows = await db("tickets").where("title", "like", `%${q}%`);
  res.json(rows);
});
