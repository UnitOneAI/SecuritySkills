# IaC Plan, State, and Provenance Edge Cases

These fixtures validate that IaC reviews require effective deployment evidence,
not only source-code scanning.

## Edge Case 1: Reviewed Code Does Not Match Applied Plan

Input evidence:

```yaml
reviewed_commit: abc123
plan_artifact:
  commit: def456
  workspace: prod
  variables_file: prod.tfvars
apply_record:
  plan_hash: null
  actor: developer-17
  auto_approve: true
```

Expected output:

- Finding ID: `IAC-PLAN-02` or `IAC-PLAN-03`
- Severity: High for production apply
- Remediation requires saved plan artifact tied to reviewed commit and approval

## Edge Case 2: State Backend Contains Secrets Without Controls

Input evidence:

```yaml
backend: local
state_file_committed: true
state_contains:
  - database_password
  - provider_token
encryption: none
locking: none
```

Expected output:

- Finding ID: `IAC-STATE-01` and `IAC-STATE-02`
- Severity: Critical
- Remediation requires secret rotation, state removal from repo, encrypted remote backend, locking, and access review

## Edge Case 3: Module Pinned to Mutable Branch

Input evidence:

```yaml
module:
  source: git::https://example.com/network.git?ref=main
provider_lock_file: missing
resource_risk: internet_facing_load_balancer
```

Expected output:

- Finding ID: `IAC-PROV-01`
- Severity: High because the module affects internet-facing resources
- Remediation requires immutable tag or commit SHA and committed lock file
