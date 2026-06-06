# Benign Fixture: Scoped npm Private Registry

```ini
# .npmrc
@company:registry=https://npm.internal.example/
registry=https://registry.npmjs.org/
always-auth=true
```

```json
{
  "name": "billing-service",
  "dependencies": {
    "@company/auth": "1.4.2",
    "express": "4.19.2"
  }
}
```

Expected decision:

- Do not flag dependency confusion solely because a private registry exists.
- Require lockfile evidence that `@company/auth` resolves to the private registry and public packages resolve to the public registry.
