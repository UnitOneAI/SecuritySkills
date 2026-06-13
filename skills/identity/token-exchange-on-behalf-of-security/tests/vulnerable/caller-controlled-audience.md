# Vulnerable: caller-controlled audience

```typescript
app.post("/exchange", requireLogin, async (req, res) => {
  const token = await tokenService.exchange({
    subjectToken: req.headers.authorization,
    audience: req.body.audience,
    scope: req.body.scope,
  });
  res.json(token);
});
```

Expected finding: `TOKEX-AUD-02` and `TOKEX-SCOPE-02`. The caller controls audience and scope without a server-side allowlist.

