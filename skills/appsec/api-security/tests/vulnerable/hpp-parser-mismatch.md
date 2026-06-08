# Vulnerable: HTTP Parameter Pollution parser mismatch

```javascript
// Gateway policy validates the first tenant_id value, but the Express handler
// later uses the last value. The authorization decision and business logic act
// on different tenants.
app.get('/api/v1/reports', requireAuth, (req, res) => {
  const tenantId = Array.isArray(req.query.tenant_id)
    ? req.query.tenant_id.at(-1)
    : req.query.tenant_id;

  // Missing duplicate-parameter rejection before the security decision.
  authorizeTenant(currentUser, tenantId);
  return res.json(listReports({ tenantId }));
});
```

Probe:

```http
GET /api/v1/reports?tenant_id=trusted-tenant&tenant_id=attacker-tenant HTTP/1.1
Authorization: Bearer user-token
```

Expected skill behavior:

- Flag as API8/API10 parser-consistency risk.
- Map impact to API1/API5 if the mismatch changes tenant, object, role, or scope authorization.
- Require evidence showing which value each layer consumed.
