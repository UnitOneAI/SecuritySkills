# Vulnerable: Service-To-Service Flow Uses Shared Static Token

This fixture should fail because a service flow relies on a shared bearer secret rather than workload identity and per-resource authorization.

```text
flow: payments-api -> orders-api
source_identity: not unique
credential_type: shared bearer token
credential_ttl: not set
secret_owner: unknown
trust_domain: not recorded
authorization_policy: broad allow if token is present
rotation_revocation: manual, no evidence
audit_evidence: destination logs record token hash only, not source workload identity
non_human_inventory: missing queue consumers and scheduled jobs
```

Expected result: fail. The Identity and Applications & Workloads pillars should be capped because the review cannot prove which workload is calling which resource, how long the credential lives, who owns it, or whether access is least privilege.
