# Vulnerable Fixture: Stale Source Reconciliation

This fixture represents an access review campaign that appears complete but is based on stale and unreconciled entitlement sources.

## Campaign Metadata

| Field | Value |
|---|---|
| Campaign | Q2 production access recertification |
| Launch time | 2026-06-07T09:00:00Z |
| In-scope systems | Okta, Salesforce, AWS production |
| Reviewer completion | 100% |
| Snapshot checksum | Missing |

## Source Evidence

| Source | Last successful export | Evidence issue |
|---|---|---|
| HRIS worker feed | 2026-05-31T02:00:00Z | Seven days older than campaign launch |
| Okta group export | 2026-06-07T08:15:00Z | No nested group expansion log retained |
| Salesforce native users | 2026-06-03T01:10:00Z | Four days older than campaign launch |
| AWS IAM bindings | 2026-06-04T12:30:00Z | No run ID or immutable object version |
| IGA campaign snapshot | 2026-06-07T09:00:00Z | Built from stale upstream feeds |

## Reconciliation Results

```text
HRIS active workers: 184
Okta active users: 191
Okta users absent from HRIS: 7
Salesforce native users: 203
Salesforce users assigned through Okta: 188
Salesforce local-only users: 15
AWS production admin grants after campaign snapshot: 3
SCIM connector last_success: 2026-06-03T01:10:00Z
SCIM connector last_status: failed_partial_delta
```

## Expected Findings

- AR-SRC-01: Review launched from stale HRIS, Salesforce, and AWS exports.
- AR-SRC-02: HRIS-to-IdP count mismatch is unresolved.
- AR-SRC-03: SCIM connector failed before campaign launch.
- AR-SRC-04: Salesforce local-only accounts were not reconciled.
- AR-SRC-06: Post-snapshot AWS admin grants were excluded from reviewer queues.
- AR-SRC-07: AWS extract lacks checksum, run ID, or immutable storage reference.

## Expected Severity

High, because the stale and unreconciled sources affect production and privileged access.
