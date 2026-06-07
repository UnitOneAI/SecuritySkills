# Vulnerable: long-lived bootstrap token and unowned break-glass recovery

This fixture should be flagged by the secrets-management skill because the
workload uses file-mounted bootstrap material with broad secret access and
documents break-glass recovery without custody, owner, test, or rotation
evidence. Placeholder strings are used; no real secret value is included.

```dockerfile
FROM node:22-alpine
COPY bootstrap-token /var/run/bootstrap-token
RUN chmod 0400 /var/run/bootstrap-token
CMD ["node", "server.js"]
```

```sh
# Entrypoint snippet
VAULT_TOKEN=$(cat /var/run/bootstrap-token)
vault kv get -format=json secret/prod/*
```

```yaml
vault_bootstrap:
  auth_method: static_token
  token_ttl: 30d
  policy: prod-read-all
  revocation_on_failed_bootstrap: false
  audit_log_sink: disabled

break_glass:
  storage: runbook.pdf
  owner: ""
  last_tested: ""
  rotation_after_use: ""
```

Expected findings:

- Critical: bootstrap material is copied into the image filesystem.
- High: bootstrap token is long-lived and grants broad `secret/prod/*` access.
- High: failed bootstrap attempts do not trigger revocation or audit logging.
- High: break-glass recovery has no owner, test evidence, or post-use rotation
  plan.
