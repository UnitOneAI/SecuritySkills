# Vulnerable: read token exchanged for write scope

```python
def exchange_for_downstream(subject_claims, requested_scope):
    issued_scope = requested_scope or "orders:write"
    return mint_token(
        sub=subject_claims["sub"],
        aud="orders-api",
        scope=issued_scope,
        ttl=3600,
    )
```

Expected finding: `TOKEX-SCOPE-01` and `TOKEX-SCOPE-03`. The issued scope is not intersected with subject and actor authority.

