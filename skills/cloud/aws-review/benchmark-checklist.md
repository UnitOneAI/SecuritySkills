# CIS AWS Foundations Benchmark -- Version-Aware Checklist

This file contains detailed checklist guidance for the AWS Security Posture Review skill. See [SKILL.md](SKILL.md) for the main process and report format.

The current default is **CIS Amazon Web Services Foundations Benchmark v5.0.0-aware** reporting using AWS Security Hub CSPM evidence when available. CIS AWS v3.0.0 remains supported only as explicit legacy mode.

---

## Benchmark Preflight

Before evaluating controls, record these fields:

| Field | Required Evidence |
|-------|-------------------|
| `benchmark_version` | `CIS AWS Foundations Benchmark v5.0.0`, or explicit legacy version such as `v3.0.0`. |
| `benchmark_source_date` | Date of AWS Security Hub docs, CIS PDF, or exported benchmark evidence. |
| `security_hub_standard_arn_or_version` | Security Hub standard ARN/version or `not supplied`. |
| `evidence_source` | Security Hub CSPM, AWS Config, AWS CLI export, Terraform, CloudFormation, CDK, manual evidence, or mixed. |
| `legacy_baseline` | `true` only when the user requested a historical benchmark. Include the reason. |
| `denominator_source` | Security Hub v5 supported controls, full CIS PDF checklist, or a documented scoped subset. |

Do not emit `<N>/62` as the current denominator. That value belongs to the old v3.0.0-oriented skill and can misstate current posture.

Use these support statuses per control:

| Status | Use When |
|--------|----------|
| Current v5 Supported | The control is part of the selected Security Hub CSPM CIS v5.0.0 evidence set. |
| Legacy | The control came from v3.0.0, v1.4.0, or v1.2.0. |
| Removed | AWS version comparison or CIS evidence shows the older requirement is no longer current. |
| Unsupported by Security Hub | The CIS requirement is not automated by Security Hub for the selected version. |
| Manual Evidence | The reviewer has non-Security Hub evidence, such as account screenshots, AWS CLI exports, or governance records. |
| Not Evaluable | Supplied evidence cannot prove pass or fail. |

---

## Current Security Hub CSPM v5.0.0 Control Catalog

AWS Security Hub CSPM documents the supported automated controls for CIS AWS Foundations Benchmark v5.0.0. Use the AWS documentation page as the mapping source, not the old v3.0.0 section denominator.

### Account and IAM

Current Security Hub v5.0.0 controls in this family include:

```
Account.1
IAM.2
IAM.3
IAM.4
IAM.5
IAM.6
IAM.9
IAM.15
IAM.16
IAM.18
IAM.22
IAM.26
IAM.27
IAM.28
```

Review focus:

- Account alternate contacts and security contacts.
- Root account access keys, root MFA, and root user activity.
- Password policy, MFA for console users, access key rotation, and unused credentials.
- Full administrative policies, support role presence, Access Analyzer, and CloudShell restrictions.
- Identity federation or centralized identity management evidence when required.

Evidence examples:

```
aws_securityhub_standards_subscription
aws_securityhub_finding_aggregator
aws_accessanalyzer_analyzer
aws_iam_account_password_policy
aws_organizations_policy
aws_ssoadmin_*
aws_identitystore_*
```

When using IaC-only evidence, mark account contacts and live credential age checks as `Not Evaluable` unless AWS CLI, Security Hub, AWS Config, or manual evidence is supplied.

### Logging, Monitoring, Config, and KMS

Current Security Hub v5.0.0 controls in this family include:

```
CloudTrail.1
CloudTrail.2
CloudTrail.4
CloudTrail.7
Config.1
KMS.4
```

Review focus:

- CloudTrail enabled and multi-region where required.
- CloudTrail log file validation.
- CloudTrail integration with CloudWatch Logs.
- CloudTrail encryption and secure log storage evidence.
- AWS Config recorder and delivery channel coverage.
- KMS key rotation for customer-managed symmetric keys.

Terraform patterns:

```hcl
resource "aws_cloudtrail" "main" {
  is_multi_region_trail      = true
  enable_logging             = true
  enable_log_file_validation = true
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn
  kms_key_id                 = aws_kms_key.cloudtrail.arn
}

resource "aws_config_configuration_recorder" "all_regions" {
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_kms_key" "managed" {
  enable_key_rotation = true
}
```

Do not treat a single Terraform trail as proof of all-region live coverage unless the repository or exported AWS evidence shows all targeted accounts and regions.

### Storage and Data Services

Current Security Hub v5.0.0 controls in this family include:

```
EFS.1
EFS.8
RDS.2
RDS.3
RDS.5
RDS.13
RDS.15
S3.1
S3.5
S3.8
S3.20
S3.22
S3.23
```

Review focus:

- S3 block public access, bucket policies, server-side encryption, secure transport, versioning, logging, and object-level events.
- EFS encryption and backup-related evidence.
- RDS encryption, public accessibility, backups, deletion protection, and automatic minor version upgrade.

Terraform patterns:

```hcl
resource "aws_s3_bucket_public_access_block" "bucket" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "db" {
  storage_encrypted          = true
  publicly_accessible        = false
  backup_retention_period    = 7
  deletion_protection        = true
  auto_minor_version_upgrade = true
}

resource "aws_efs_file_system" "fs" {
  encrypted = true
}
```

Account-level S3 block public access can reduce exposure, but do not hide a conflicting bucket policy. Report both the effective account guardrail and the risky resource-level configuration.

### EC2 and Network Exposure

Current Security Hub v5.0.0 controls in this family include:

```
EC2.2
EC2.6
EC2.7
EC2.8
EC2.21
EC2.53
EC2.54
```

Review focus:

- Default security group restrictions.
- Security groups and network ACLs that expose SSH, RDP, databases, or administrative ports to `0.0.0.0/0` or `::/0`.
- VPC flow logs.
- EC2 instance metadata service v2 for instances and launch templates.
- EBS encryption by default and related storage controls.

Terraform patterns:

```hcl
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}

resource "aws_security_group_rule" "bad_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_launch_template" "app" {
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_flow_log" "vpc" {
  traffic_type = "ALL"
}

resource "aws_ebs_encryption_by_default" "default" {
  enabled = true
}
```

For IPv6, check `ipv6_cidr_blocks = ["::/0"]` and CloudFormation equivalents.

---

## Version Mapping and Scoring Rules

Use this table format when the evidence includes multiple CIS versions:

| Security Hub Control ID | CIS v5 Requirement | Legacy v3/v1.x Requirement | Support Status | Evidence Source | Assessment Status |
|-------------------------|--------------------|----------------------------|----------------|-----------------|-------------------|
| IAM.4 | <from selected mapping> | <legacy mapping if supplied> | Current v5 Supported | Security Hub CSPM | Pass/Fail |
| EC2.54 | <from selected mapping> | none or not supplied | Current v5 Supported | Terraform + Security Hub | Pass/Fail |
| <legacy ID> | none | CIS v3.0.0 <ID> | Legacy | historical report | Not counted in v5 score |

Scoring rules:

1. Count only controls in the selected benchmark denominator.
2. Do not count `Legacy`, `Removed`, `Unsupported by Security Hub`, or `Not Evaluable` as passing current v5 controls.
3. A Security Hub finding can prove live-account status only for the account, region, and standard version named in the evidence.
4. IaC evidence can prove intended configuration, not live runtime compliance, unless backed by AWS Config, Security Hub, or AWS CLI exports.
5. If Security Hub and IaC disagree, report the disagreement and prefer live Security Hub/AWS Config evidence for current posture.

---

## Legacy CIS AWS v3.0.0 Checklist

Use this section only when `legacy_baseline: true` is declared.

Legacy v3.0.0 grouped controls into five domains: Identity and Access Management, Storage, Logging, Monitoring, and Networking. Historical reports may still mention the old denominator of 62 recommendations. In a current v5.0.0 report, those IDs must be mapped or marked legacy before scoring.

### Legacy Identity and Access Management Examples

- Root access keys, root MFA, and root usage restrictions.
- IAM password policy length and reuse.
- MFA for console users.
- Access key age, unused credentials, and direct user policy attachments.
- Full administrative policies and support role presence.
- IAM Access Analyzer and CloudShell restrictions.

### Legacy Storage Examples

- S3 secure transport bucket policy.
- S3 public access block at bucket and account level.
- EBS, RDS, and EFS encryption.
- RDS public accessibility and automatic minor version upgrade.

### Legacy Logging and Monitoring Examples

- Multi-region CloudTrail.
- CloudTrail log validation, CloudWatch Logs integration, and KMS encryption.
- AWS Config enabled.
- VPC flow logs.
- CloudWatch metric filters and alarms for critical account, IAM, KMS, S3, VPC, and Organizations changes.

### Legacy Networking Examples

- No unrestricted NACL or security group ingress to SSH/RDP.
- No unrestricted IPv6 admin-port ingress.
- Default security group has no ingress or egress rules.
- VPC peering routes are least access.
- EC2 IMDSv2 required for instances and launch templates.

---

## Output Checklist

Every final report must include:

- Benchmark version and source date.
- Security Hub standard ARN/version or explanation that it was not supplied.
- Evidence source for every finding.
- Support status for every finding.
- Denominator source.
- Separate counts for current, legacy, removed, unsupported, manual, and not-evaluable controls.
- Clear statement when the review is IaC-only and cannot prove live AWS account posture.
