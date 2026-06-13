# Vulnerable: actor provenance lost

```json
{
  "sub": "svc-support-console",
  "aud": "billing-api",
  "scope": "refund:create",
  "exp": 1893456000
}
```

Expected finding: `TOKEX-ACTOR-01` and `TOKEX-ACTOR-02`. The token no longer records the target user or operator context, so downstream audit cannot prove who acted for whom.

