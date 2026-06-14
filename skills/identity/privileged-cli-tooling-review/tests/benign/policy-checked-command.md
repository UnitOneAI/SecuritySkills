# Benign: centralized policy check before mutation

```python
decision = policy.check(
    actor=current_operator(),
    action="support.disable_mfa",
    tenant=args.tenant,
    resource=args.user_id,
    approval=args.ticket,
)
if not decision.allowed:
    raise SystemExit("not authorized")
audit.log_privileged_cli(decision, dry_run=args.dry_run)
```

Expected result: do not flag missing authorization when actor, action, tenant, resource, approval, and audit evidence are enforced centrally.

