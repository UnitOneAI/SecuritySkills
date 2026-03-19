# AWS Detection Patterns Reference

Extracted from [benchmark-checklist.md](../benchmark-checklist.md). This file consolidates inline regex and grep patterns used for CIS AWS v3.0.0 detection.

---

## IAM Detection Patterns

### Root Account Key Detection (CIS 1.4)

```
root.*access.key
aws_iam_access_key.*root
```

### Credential Rotation (CIS 1.12, 1.14)

```
aws_config_config_rule.*iam-user-unused-credentials-check
max_credential_age
access-keys-rotated
maxAccessKeyAge
```

### Direct User Policy Attachment (CIS 1.15)

```
# BAD: Direct user policy attachment
aws_iam_user_policy_attachment
aws_iam_user_policy

# GOOD: Group-based policy attachment
aws_iam_group_policy_attachment
aws_iam_group_membership
```

### Overly Permissive Policies (CIS 1.16)

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

### IAM MFA Enforcement (CIS 1.10)

```json
{
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

### MFA Enforcement via SCP (CIS 1.5, 1.6)

```
aws_iam_account_password_policy
aws_organizations_policy.*Deny.*root
```

### Access Analyzer (CIS 1.20)

```
aws_accessanalyzer_analyzer
type = "ACCOUNT"
```

### Identity Federation (CIS 1.21)

```
aws_ssoadmin_managed_policy_attachment
aws_identitystore
aws_organizations_organization
```

---

## Storage Detection Patterns

### S3 Public Access Block (CIS 2.1.4)

```
aws_s3_bucket_public_access_block
block_public_acls\s*=\s*true
block_public_policy\s*=\s*true
ignore_public_acls\s*=\s*true
restrict_public_buckets\s*=\s*true
aws_s3_account_public_access_block
```

### EBS Encryption (CIS 2.2.1)

```
aws_ebs_encryption_by_default
enabled\s*=\s*true
```

### RDS Encryption (CIS 2.3.1)

```
storage_encrypted\s*=\s*true
kms_key_id
```

### RDS Public Access (CIS 2.3.3)

```
publicly_accessible\s*=\s*true
publicly_accessible\s*=\s*false
```

### EFS Encryption (CIS 2.4.1)

```
aws_efs_file_system
encrypted\s*=\s*true
```

---

## Logging Detection Patterns

### CloudTrail Configuration (CIS 3.1, 3.2, 3.4, 3.7)

```
is_multi_region_trail\s*=\s*true
enable_logging\s*=\s*true
enable_log_file_validation\s*=\s*true
cloud_watch_logs_group_arn
kms_key_id
```

### AWS Config (CIS 3.5)

```
aws_config_configuration_recorder
aws_config_delivery_channel
all_supported\s*=\s*true
include_global_resource_types\s*=\s*true
```

### KMS Key Rotation (CIS 3.8)

```
enable_key_rotation\s*=\s*true
```

### VPC Flow Logs (CIS 3.9)

```
aws_flow_log
traffic_type\s*=\s*"ALL"
```

---

## Monitoring Detection Patterns

### Security Hub (CIS 4.16)

```
aws_securityhub_account
aws_securityhub_standards_subscription
```

### CloudWatch Metric Filters (CIS 4.1-4.15)

```
aws_cloudwatch_log_metric_filter
aws_cloudwatch_metric_alarm
alarm_actions
```

---

## Networking Detection Patterns

### Unrestricted Admin Ports (CIS 5.1, 5.2, 5.3)

```
cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]
ipv6_cidr_blocks\s*=\s*\["::/0"\]
cidr_block\s*=\s*"0\.0\.0\.0/0"
from_port\s*=\s*22
from_port\s*=\s*3389
```

### Default Security Group (CIS 5.4)

```
aws_default_security_group
```

### IMDSv2 Enforcement (CIS 5.6)

```
http_tokens\s*=\s*"required"
metadata_options
aws_launch_template.*metadata_options
```
