# Benign: persisted query re-checks authorization at execution time

This sample should not be reported for registration-only authorization. The persisted query registry is only an allowlist, while tenant and role checks still run for every execution.

```javascript
export async function executePersistedQuery(ctx, operationHash, variables) {
  const operation = await persistedQueries.requireAllowed(operationHash);
  await requireTenantMember(ctx.user, ctx.tenantId);
  await requireOperationPermission(ctx.user, operation.requiredPermission);

  return graphql({
    schema,
    source: operation.source,
    variableValues: variables,
    contextValue: ctx,
  });
}
```

Expected result:

- No finding for APQ or persisted query cache authorization.
- Reviewer should confirm downstream resolvers keep object and field-level checks.
