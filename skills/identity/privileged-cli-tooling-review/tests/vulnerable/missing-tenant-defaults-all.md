# Vulnerable: missing tenant defaults to all tenants

```typescript
const tenant = argv.tenant || "*";
await featureFlags.setFlag({ tenant, flag: argv.flag, enabled: argv.enabled });
```

Expected finding: `PCLI-BLAST-01`. Missing scope broadens a privileged mutation to every tenant.

