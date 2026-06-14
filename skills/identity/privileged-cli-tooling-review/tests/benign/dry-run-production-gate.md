# Benign: explicit production gate and dry-run

```typescript
if (env === "production" && argv.confirmProduction !== "CHANGE-PROD") {
  throw new Error("explicit production confirmation required");
}

const changes = await previewRoleChanges(argv.tenant, argv.user, argv.role);
audit.write({ actor, tenant: argv.tenant, action: "role.change", dryRun: argv.dryRun });
if (!argv.dryRun) {
  await applyRoleChanges(changes);
}
```

Expected result: do not flag unsafe production defaults when production is explicit, tenant scope is required, dry-run is supported, and audit evidence is written.

