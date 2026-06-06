# GCP VPC Service Controls Edge Cases

These fixtures validate that `gcp-review` captures managed-service data
exfiltration risks that are not visible from firewall rules alone.

## Edge Case 1: Sensitive BigQuery Project Outside Perimeter

Input evidence:

```yaml
project: analytics-prod
data_classification: restricted
services:
  - bigquery.googleapis.com
  - storage.googleapis.com
vpc_service_controls:
  perimeter: null
public_access:
  bigquery_dataset_all_users: false
```

Expected output:

- Finding ID: `GCP-VPCSC-01`
- Severity: High because restricted data is processed by managed services outside a perimeter
- Remediation requires perimeter assignment and restricted service inventory

## Edge Case 2: Broad Egress Policy to Any Project

Input evidence:

```yaml
perimeter: prod-data-perimeter
egress_policy:
  principals: ["*"]
  resources: ["projects/*"]
  services:
    - bigquery.googleapis.com
  justification: "temporary analytics migration"
  owner: null
  expiry: null
```

Expected output:

- Finding ID: `GCP-VPCSC-03` and `GCP-VPCSC-07`
- Severity: High
- Require scoped principals, destination projects, owner, expiry, and rollback plan

## Edge Case 3: Dry-Run Violations Ignored

Input evidence:

```yaml
perimeter: pii-services-dry-run
mode: dry_run
dry_run_violations:
  count: 132
  oldest: "2026-04-01T00:00:00Z"
  reviewed: false
enforcement_date: null
```

Expected output:

- Finding ID: `GCP-VPCSC-05`
- Do not mark perimeter readiness as pass
- Require owner disposition for dry-run violations before enforcement
