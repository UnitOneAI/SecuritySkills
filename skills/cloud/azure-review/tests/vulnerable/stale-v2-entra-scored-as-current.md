# Vulnerable: Stale v2.1.0 Entra Controls Scored as Current Azure

## Azure Security Posture Assessment Report

### Environment

- Subscription/Repository: example-platform
- Date: 2026-06-03
- Framework: CIS Microsoft Azure Foundations Benchmark v2.1.0
- Files reviewed: `terraform/azure/*.tf`, `entra/conditional-access.json`

### Executive Summary

- Total CIS recommendations evaluated: 88
- Passed: 80
- Failed: 8
- Not Applicable: 0
- Not Evaluable: 0
- Overall compliance: 91%

### Section Scores

| Section | Description | Passed | Failed | N/A | Compliance |
|---------|-------------|--------|--------|-----|------------|
| 1 | Identity and Access Management | 11 | 2 | 0 | 85% |
| 2 | Microsoft Defender for Cloud | 14 | 1 | 0 | 93% |
| 3 | Storage Accounts | 12 | 1 | 0 | 92% |
| 4 | Database Services | 10 | 1 | 0 | 91% |
| 5 | Logging and Monitoring | 13 | 1 | 0 | 93% |
| 6 | Networking | 6 | 1 | 0 | 86% |
| 7 | Virtual Machines | 7 | 0 | 0 | 100% |
| 8 | Key Vault | 7 | 0 | 0 | 100% |
| 9 | App Service | 6 | 1 | 0 | 86% |

## Why This Should Be Flagged

This report presents CIS Azure v2.1.0 as current, includes Entra ID controls in Azure Foundations scoring, and omits benchmark source date, legacy baseline, Entra scope handling, deleted/migrated counts, and current v6.0.0 mapping evidence.
