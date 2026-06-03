# Vulnerable: Stale v2 Report With Mixed Organization Scope

## GCP Security Posture Assessment Report

### Environment

- Project/Organization: `organizations/1234567890`
- Date: 2026-06-03
- Framework: CIS Google Cloud Platform Foundation Benchmark v2.0.0
- Files reviewed: `terraform/gcp/*.tf`, `org-policies/*.yaml`

### Executive Summary

- Total CIS recommendations evaluated: 44
- Passed: 41
- Failed: 3
- Not Applicable: 0
- Not Evaluable: 0
- Overall compliance: 93%

### Section Scores

| Section | Description | Passed | Failed | N/A | Compliance |
|---------|-------------|--------|--------|-----|------------|
| 1 | Identity and Access Management | 17 | 1 | 0 | 94% |
| 2 | Logging and Monitoring | 12 | 1 | 0 | 92% |
| 3 | Networking | 9 | 1 | 0 | 90% |
| 4 | Virtual Machines | 4 | 0 | 0 | 100% |
| 5 | Storage | 2 | 0 | 0 | 100% |
| 6 | Cloud SQL | 5 | 0 | 0 | 100% |
| 7 | BigQuery | 3 | 0 | 0 | 100% |

## Why This Should Be Flagged

This report presents CIS GCP v2.0.0 as current, mixes project and organization scope in one score, and omits benchmark source date, legacy baseline, scope level, scope evidence, denominator source, and current v5.0.0 mapping.
