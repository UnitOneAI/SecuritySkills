# Benign: request-scoped DataLoader with tenant-aware cache key

This sample should not be reported as cross-tenant cache leakage. The loader is constructed for each request, the database query includes `tenantId`, and the cache key includes tenant and subject context.

```javascript
export function buildContext(req) {
  const ctx = {
    tenantId: req.auth.tenantId,
    subjectId: req.auth.sub,
  };

  ctx.loaders = {
    userById: new DataLoader(
      ids => User.find({ tenantId: ctx.tenantId, id: { $in: ids } }),
      { cacheKeyFn: id => `${ctx.tenantId}:${ctx.subjectId}:${id}` }
    ),
  };

  return ctx;
}
```

Expected result:

- No finding for DataLoader cache scope.
- Reviewer may still inspect field-level authorization for sensitive properties returned by `User`.
