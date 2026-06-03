# Vulnerable: Stale CIS AWS v3 Report Presented as Current

## AWS Security Posture Assessment Report

### Environment

- Account/Repository: example-production
- Date: 2026-06-03
- Framework: CIS Amazon Web Services Foundations Benchmark v3.0.0
- Files reviewed: `terraform/aws/*.tf`

### Executive Summary

- Total CIS recommendations evaluated: 59/62
- Passed: 57
- Failed: 2
- Not Applicable: 0
- Not Evaluable: 3
- Overall compliance: 97%

### Section Scores

| Section | Description | Passed | Failed | N/A | Compliance |
|---------|-------------|--------|--------|-----|------------|
| 1 | Identity and Access Management | 21/22 | 1 | 0 | 95% |
| 2 | Storage | 10/10 | 0 | 0 | 100% |
| 3 | Logging | 10/11 | 1 | 0 | 91% |
| 4 | Monitoring | 16/16 | 0 | 0 | 100% |
| 5 | Networking | 6/6 | 0 | 0 | 100% |

## Why This Should Be Flagged

This report claims current posture using the old v3.0.0 framework and hard-coded `62` denominator. It does not record benchmark source date, Security Hub standard ARN/version, legacy baseline status, evidence source, control support status, removed/unsupported control counts, or a v5.0.0 mapping.
