# Benign: narrowed audience and scope

```python
policy = exchange_policy.lookup(actor.client_id, request.resource)
allowed_scope = intersect(subject.scopes, actor.scopes, policy.allowed_scopes)
if request.scope - allowed_scope:
    raise Forbidden("scope not allowed")

return mint_token(
    sub=subject.sub,
    actor=actor.client_id,
    aud=policy.downstream_audience,
    scope=request.scope,
    ttl=300,
)
```

Expected result: do not flag privilege widening. The issued token is short-lived and scoped to the exact downstream audience.

