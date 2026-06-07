# Benign Fixture: Fresh Source Reconciliation

This fixture represents an access review campaign with current, traceable, and reconciled entitlement sources.

## Campaign Metadata

| Field | Value |
|---|---|
| Campaign | Q2 production access recertification |
| Launch time | 2026-06-07T09:00:00Z |
| In-scope systems | Okta, Salesforce, AWS production |
| Reviewer completion | 94% in progress |
| Snapshot checksum | sha256:5f99b763a2e6b3f3f6d3ed2b8b6e7e5b5fc0b5f3129bb92fa3be68a8073f51a4 |

## Source Evidence

| Source | Last successful export | Evidence retained |
|---|---|---|
| HRIS worker feed | 2026-06-07T07:30:00Z | object version hris-q2-2026-v18 |
| Okta group export | 2026-06-07T08:00:00Z | nested group expansion job okta-expand-7781 |
| Salesforce native users | 2026-06-07T08:10:00Z | SCIM sync run scim-sfdc-9042 succeeded |
| AWS IAM bindings | 2026-06-07T08:20:00Z | export run aws-prod-iam-4419 |
| IGA campaign snapshot | 2026-06-07T09:00:00Z | immutable snapshot iga-q2-prod-2026 |

## Reconciliation Results

```text
HRIS active workers: 184
Okta active users: 184
Okta users absent from HRIS: 0
Salesforce native users: 188
Salesforce users assigned through Okta: 188
Salesforce local-only users: 0
AWS production admin grants after campaign snapshot: 0
SCIM connector last_success: 2026-06-07T08:10:00Z
SCIM connector last_status: succeeded
```

## Expected Result

No AR-SRC finding should be raised. The review population is fresh, reconciled, and replayable during audit.
