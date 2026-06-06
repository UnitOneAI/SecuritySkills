# SOC 2 Evidence Period and Sampling Edge Cases

Use these cases to validate that `soc2-gap` does not treat any existing artifact as audit-ready Type II evidence without period coverage, sample sufficiency, and boundary mapping.

## Case 1: Access review evidence outside the audit period

**Input**

```yaml
criterion: CC6.1
control: quarterly access review
planned_audit_period:
  start: 2026-01-01
  end: 2026-06-30
evidence:
  artifact: access-review.xlsx
  evidence_date: 2025-01-15
  audit_period_covered: missing
  population: missing
  sample_size: missing
  system_boundary: production only
  owner: missing
```

**Expected result**

Do not score above 2. The artifact exists, but it is stale, outside the audit period, ownerless, and does not define population or sample coverage.

## Case 2: Change management sample covers only one month

**Input**

```yaml
criterion: CC8.1
control: production change approval
planned_audit_period:
  start: 2026-01-01
  end: 2026-06-30
evidence:
  artifact: pr-review-sample.csv
  supports: operating_effectiveness
  audit_period_covered: 2026-06-01 to 2026-06-30
  population: all production changes
  sample_size: 5 of 214
  sample_method: judgmental
  exceptions_found: 0
  system_boundary: api service only
```

**Expected result**

Cap at 3 unless the report documents why a one-month, five-item, single-service sample is sufficient for the planned Type II period and system boundary.

## Case 3: Vulnerability management evidence has unresolved exceptions

**Input**

```yaml
criterion: CC7.1
control: scheduled vulnerability scanning
evidence:
  artifact: scan-results-and-remediation.csv
  audit_period_covered: 2026-01-01 to 2026-06-30
  population: all internet-facing assets
  sample_size: full population
  exceptions_found: 12 critical findings past SLA
  exception_remediation: missing
  retest_evidence: missing
```

**Expected result**

Cap at 3 or lower. Full-period evidence is present, but unresolved exceptions without remediation and retest evidence prevent a managed readiness score.

## Case 4: Complete Type II evidence record

**Input**

```yaml
criterion: CC6.5
control: timely access deprovisioning
planned_audit_period:
  start: 2026-01-01
  end: 2026-06-30
evidence:
  artifact: offboarding-sample-and-iam-log-export.zip
  supports: operating_effectiveness
  audit_period_covered: 2026-01-01 to 2026-06-30
  evidence_date: 2026-06-30
  collection_date: 2026-07-02
  source_system: HRIS and IAM
  evidence_owner: security-compliance
  retention_location: grc://soc2/2026/cc6.5
  system_boundary: all in-scope workforce identities and production IAM
  population: 48 terminated users during audit period
  sample_size: 15 of 48
  sample_method: random
  exceptions_found: 1
  exception_remediation: ticket IAM-991 retested pass
```

**Expected result**

Eligible for score 4 if the control is otherwise implemented and the exception remediation evidence is complete. The record covers the period, population, sample method, owner, source, retention location, system boundary, and retest result.
