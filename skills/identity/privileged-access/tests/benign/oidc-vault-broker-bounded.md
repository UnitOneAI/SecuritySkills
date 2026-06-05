---
case: oidc-vault-broker-bounded
expected: benign
finding_ids: []
---

# Benign: OIDC Vault Broker With Bounded Scope

```yaml
automation_identity: deploy-secret-broker
owner: platform-security
purpose: issue short-lived database credentials to production deploy jobs
auth_method: OIDC/JWT to Vault
secret_zero:
  storage: none in CI
  exchange: workload token exchanged at runtime
policy_scope:
  namespace: apps/payments/prod
  permissions:
    - read database/creds/payments-deploy
    - create bounded child tokens only
  denied:
    - vault policy update
    - audit export disable
    - safe export
token_controls:
  ttl: 15m
  max_ttl: 1h
  renewable: false
audit_evidence:
  token_accessor_logged: true
  job_id_logged: true
  target_secret_logged: true
  forwarded_to_siem: true
revocation_evidence:
  parent_revoke_tested: true
  child_tokens_revoked: true
  leases_revoked: true
confidence: strong
```

Reviewer expectation: do not flag merely because the automation calls Vault. Verify claim mapping, path scope, TTL/max TTL, audit correlation, and revocation evidence.
