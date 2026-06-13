# Benign: ordinary profile display-name edit

```typescript
app.post("/profile/display-name", requireLogin, async (req, res) => {
  await profiles.setDisplayName(req.user.id, req.body.displayName);
  res.sendStatus(204);
});
```

Expected result: do not require step-up for a read-only or low-impact profile preference unless local policy classifies this field as sensitive.

