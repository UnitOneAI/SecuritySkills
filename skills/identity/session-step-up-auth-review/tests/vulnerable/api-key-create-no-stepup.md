# Vulnerable: API key creation without fresh authentication

```typescript
app.post("/api/keys", requireLogin, async (req, res) => {
  const key = await apiKeys.create({
    userId: req.user.id,
    scopes: req.body.scopes,
    expiresAt: req.body.expiresAt,
  });
  res.json({ token: key.token });
});
```

Expected finding: `STEPUP-INV-04`. A high-impact credential can be created from an ordinary session.

