# Vulnerable: process-wide GraphQL DataLoader cache

This sample should be reported because the loader is module-scoped and caches tenant-specific user records by `id` only. A request from tenant A can warm the cache for `user-123`, and a later request from tenant B can receive the cached object if the same identifier is used or guessed.

```javascript
import DataLoader from "dataloader";

const userById = new DataLoader(async ids => {
  return User.find({ id: { $in: ids } });
});

export const resolvers = {
  Query: {
    user: async (_, { id }, ctx) => {
      await requireTenantMember(ctx.user, ctx.tenantId);
      return userById.load(id);
    },
  },
};
```

Expected finding:

- OWASP API Risk: API1:2023 BOLA and API3:2023 object property authorization.
- Evidence: singleton loader lifecycle and cache key omits tenant, subject, role, and authorization scope.
- Remediation: create loaders per request and query by tenant plus object ID.
