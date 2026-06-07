# Benign: constrained OIDC bootstrap with tested recovery evidence

This fixture should pass the bootstrap and recovery gates because the pipeline
uses OIDC to obtain short-lived Vault access, trust conditions are constrained,
and break-glass recovery evidence is documented without exposing credential
values.

```yaml
github_actions_oidc:
  issuer: https://token.actions.githubusercontent.com
  audience: vault://prod-secrets
  subject: repo:example/payments:environment:production
  branch: refs/heads/main
  workflow: .github/workflows/deploy.yml

vault_jwt_role:
  role: payments-prod-deploy
  bound_audiences:
    - vault://prod-secrets
  bound_subject: repo:example/payments:environment:production
  bound_claims:
    repository: example/payments
    ref: refs/heads/main
    environment: production
  token_ttl: 15m
  token_max_ttl: 20m
  policies:
    - payments-prod-read
```

```hcl
path "secret/data/prod/payments/*" {
  capabilities = ["read"]
}

path "secret/data/prod/*" {
  capabilities = ["deny"]
}
```

```yaml
bootstrap_controls:
  revocation_on_failed_bootstrap: true
  audit_log_sink: siem-prod
  token_reuse_allowed: false
  image_contains_bootstrap_material: false

break_glass:
  storage: sealed emergency access vault
  approval: two-person review
  owner: security-operations
  last_tested: 2026-05-30
  rotation_after_use: required within 1h
  credential_value_recorded_here: false
```

Expected result:

- Pass: bootstrap identity is short-lived and constrained by issuer, audience,
  repository, branch, environment, and workflow.
- Pass: Vault policy scopes access to the workload-specific secret path.
- Pass: failed bootstrap revocation and audit evidence are present.
- Pass: break-glass custody, owner, test cadence, and post-use rotation are
  documented without exposing a secret value.
