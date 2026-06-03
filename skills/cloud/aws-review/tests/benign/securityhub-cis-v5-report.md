# Benign: CIS AWS v5 Security Hub Evidence Report

## AWS Security Posture Assessment Report

### Environment

- Account/Repository: example-production
- Date: 2026-06-03
- Framework: CIS Amazon Web Services Foundations Benchmark v5.0.0
- Benchmark source date: 2026-06-03
- Security Hub standard ARN/version: `arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/5.0.0`
- Legacy baseline: false
- Evidence sources: Security Hub CSPM, AWS Config, Terraform
- Files reviewed: `securityhub/cis-v5-findings.json`, `terraform/aws/*.tf`

### Executive Summary

- Total controls evaluated: 40/40 from AWS Security Hub CSPM CIS v5.0.0 supported controls
- Passed: 38
- Failed: 2
- Legacy controls: 0
- Removed or unsupported controls: 0
- Not Applicable: 0
- Not Evaluable: 0

### Section Scores

| Control Family | Evidence Source | Supported | Passed | Failed | N/A | Not Evaluable | Compliance |
|----------------|-----------------|-----------|--------|--------|-----|---------------|------------|
| Account/IAM | Security Hub v5 + manual | 14 | 13 | 1 | 0 | 0 | 93% |
| Logging/Monitoring/KMS | Security Hub v5 + AWS Config | 6 | 6 | 0 | 0 | 0 | 100% |
| Storage/Data | Security Hub v5 + Terraform | 13 | 12 | 1 | 0 | 0 | 92% |
| EC2/Network | Security Hub v5 + Terraform | 7 | 7 | 0 | 0 | 0 | 100% |

### Detailed Findings

#### [Security Hub IAM.4] Root user MFA

- **Status:** Pass
- **Support Status:** Current v5 Supported
- **Benchmark Version:** CIS AWS Foundations Benchmark v5.0.0
- **Evidence Source:** Security Hub CSPM

#### [Security Hub S3.8] S3 block public access

- **Status:** Fail
- **Support Status:** Current v5 Supported
- **Benchmark Version:** CIS AWS Foundations Benchmark v5.0.0
- **Evidence Source:** Security Hub CSPM + Terraform
- **Evidence:** Account-level block is enabled, but one bucket-level block is missing `restrict_public_buckets = true`.
