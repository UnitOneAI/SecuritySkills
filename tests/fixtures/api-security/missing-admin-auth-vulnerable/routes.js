app.get("/api/admin/users", (req, res) => {
  res.json(userStore.listAll());
});
