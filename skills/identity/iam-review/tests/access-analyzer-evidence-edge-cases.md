# IAM Analyzer Evidence Edge Cases

These fixtures validate that the IAM review does not blindly trust analyzer
recommendations or stale telemetry when producing least-privilege findings.

## Edge Case 1: External Access Finding Without Ownership

Input evidence:

```json
{
  "source": "AWS IAM Access Analyzer",
  "findingId": "abc123",
  "resource": "arn:aws:s3:::finance-prod-ledger",
  "principal": "arn:aws:iam::999999999999:role/vendor-export",
  "condition": {},
  "lastAnalyzedAt": "2026-06-05T10:00:00Z",
  "ownerDisposition": null
}
```

Expected output:

- Finding ID: `IAM-PRIV-09`
- Severity: High
- Evidence freshness includes `lastAnalyzedAt`
- Owner / Exception is `none`
- Remediation requires owner triage, condition constraints, and expiry

## Edge Case 2: Unused Permission Recommendation With Stale Telemetry

Input evidence:

```json
{
  "source": "GCP IAM Recommender",
  "principal": "serviceAccount:quarterly-report@project.iam.gserviceaccount.com",
  "recommendation": "remove bigquery.jobs.create",
  "observationPeriodDays": 30,
  "workloadPattern": "quarterly financial close",
  "lastAuditLogWindowEnds": "2026-03-31T23:59:59Z"
}
```

Expected output:

- Finding ID: `IAM-PRIV-10` or `IAM-PRIV-14`
- Do not recommend immediate removal
- Require business-owner validation and a longer observation window
- Rollback Path names the owner responsible for restoring access

## Edge Case 3: Cross-Tenant Grant Missing Audience Constraint

Input evidence:

```json
{
  "source": "Entra workload identity federation",
  "appId": "11111111-2222-3333-4444-555555555555",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:example/payments:*",
  "audiences": ["api://AzureADTokenExchange"],
  "expiry": null,
  "approver": null
}
```

Expected output:

- Finding ID: `IAM-PRIV-11` or `IAM-PRIV-12`
- Severity: High when the grant reaches production resources
- Owner / Exception includes missing approver and expiry
- Remediation tightens subject/audience constraints and adds an exception expiry
