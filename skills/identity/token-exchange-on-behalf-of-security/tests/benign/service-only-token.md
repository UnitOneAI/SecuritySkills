# Benign: service-only token with no user delegation

```json
{
  "sub": "svc-inventory-sync",
  "aud": "inventory-api",
  "scope": "inventory:read",
  "token_use": "service",
  "exp": 1770000000
}
```

Expected result: do not treat every service token as on-behalf-of delegation. Review normal service authentication separately unless the token represents a user action.

