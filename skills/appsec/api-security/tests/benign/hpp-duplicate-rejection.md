# Benign: duplicate security parameters rejected before security decisions

```javascript
function singleQueryParam(req, name) {
  const value = req.query[name];
  if (Array.isArray(value)) {
    throw new BadRequestError(`Duplicate ${name} parameters are not allowed`);
  }
  return value;
}

app.get('/api/v1/reports', requireAuth, (req, res) => {
  const tenantId = singleQueryParam(req, 'tenant_id');
  authorizeTenant(currentUser, tenantId);
  return res.json(listReports({ tenantId }));
});
```

Expected skill behavior:

- Do not flag merely because the endpoint has a tenant parameter.
- Accept the control when duplicate values are rejected before authorization, cache-key generation, signing, audit logging, and business logic.
