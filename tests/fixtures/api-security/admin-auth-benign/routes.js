app.get("/api/admin/users", requireAdmin, (req, res) => {
  res.json(userStore.listAll());
});
