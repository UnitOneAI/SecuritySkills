---
case: broad-pam-api-token
expected: vulnerable
finding_ids:
  - PAM-AUTO-01
  - PAM-AUTO-05
  - PAM-AUTO-10
---

# Vulnerable: Broad PAM API Token In CI

```yaml
ci_job: rotate one application password
pam_api_identity:
  name: ci-rotation-api
  owner: shared-mailbox
  token_scope:
    - admin
    - all safes
    - all secrets
    - audit export
  ttl: 90 days
  max_ttl: unknown
  stored_in: GitHub Actions secret
  child_tokens: unknown
audit_evidence:
  login_events_only: true
  per_secret_read_correlation: false
  per_rotation_job_correlation: false
revocation_evidence:
  parent_token_revoke_path: documented
  child_tokens_or_leases: not reviewed
confidence: partial
```

Reviewer expectation: report the API token as a privileged broker identity because its scope exceeds the job, audit evidence does not correlate token use to target secrets/actions, and the long-lived bearer token is stored in CI.
