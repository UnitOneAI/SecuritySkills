# Vulnerable Fixture: npm Dependency Confusion

```ini
# .npmrc
registry=https://registry.npmjs.org/
```

```json
{
  "name": "billing-service",
  "dependencies": {
    "company-auth": "1.4.2"
  }
}
```

Expected findings:

- `SCA-ATTACK-01` High: internal-looking package name is unscoped and can be claimed on the public registry.
- `SCA-ATTACK-02` High: no namespace-to-private-registry binding exists.

Benign contrast: `@company/auth` with `@company:registry=https://npm.internal.example/` and a lockfile resolving to that registry.
