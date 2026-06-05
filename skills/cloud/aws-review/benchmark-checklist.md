# CIS AWS Foundations Benchmark -- Version-Aware Detailed Checklist

This file contains detailed CIS benchmark checklist items for the AWS Security Posture Review skill. See [SKILL.md](SKILL.md) for the main skill definition, process overview, benchmark-version preflight, and output format.

The original checklist was written for CIS AWS Foundations Benchmark v3.0.0. Current reviews must first identify the selected benchmark version and mapping source. Use this file as evidence guidance and as a legacy v3.0.0 control map; do not treat the fixed v3.0.0 section counts as the denominator for a v5.0.0 Security Hub CSPM assessment.

---

## Benchmark Version Preflight

Before applying any checklist item, capture the benchmark context:

| Field | How to Capture |
|-------|----------------|
| `benchmark_version` | From the user request, Security Hub standards subscription, GRC export, or report header. |
| `security_hub_standard_arn_or_version` | Look for `cis-aws-foundations-benchmark/v/<version>` in Security Hub subscriptions or exported findings. |
| `control_mapping_source` | AWS Security Hub CSPM version comparison, official CIS material, or an approved internal control crosswalk. |
| `benchmark_source_date` | Date of the AWS/CIS mapping source or internal GRC mapping. |
| `legacy_baseline` | Set to true only when v3.0.0 or older was intentionally selected. |

Use this support status vocabulary for each row in the final mapping table:

| Status | Checklist Behavior |
|--------|--------------------|
| `current` | Score normally for the selected benchmark version. |
| `legacy` | Preserve for migration context, but do not count as current v5.0.0 coverage. |
| `removed` | Do not report as a current failure. Explain that the requirement was removed for the selected version. |
| `unsupported` | Do not score from Security Hub CSPM alone. Request manual evidence if the risk still matters. |
| `manual` | Requires evidence outside repository/IaC inspection. |
| `not_evaluable_from_supplied_evidence` | Applies in principle, but available files cannot prove pass/fail. |

Security Hub CSPM evidence to search for:

```
cis-aws-foundations-benchmark/v/5.0.0
cis-aws-foundations-benchmark/v/3.0.0
aws_securityhub_standards_subscription
standards_subscription_arn
StandardsArn
GeneratorId
Compliance.SecurityControlId
Compliance.AssociatedStandards
```

---

## Section 1 -- Identity and Access Management

Evaluate IAM configurations against the selected CIS AWS benchmark version. The legacy items below map to the v3.0.0 checklist and should be cross-checked against the selected version before scoring.

### CIS 1.1 -- Maintain current contact details

Verify that account contact information is configured. Check for `aws_account_alternate_contact` resources in Terraform or equivalent.

### CIS 1.2 -- Ensure security contact information is registered

Look for security-specific alternate contact configuration.

### CIS 1.4 -- Ensure no 'root' account access key exists

**Grep patterns:**

```
# Check for root account key references
root.*access.key
aws_iam_access_key.*root
```

### CIS 1.5 -- Ensure MFA is enabled for the 'root' user account

Check for `aws_iam_account_password_policy` or SCP policies enforcing root MFA.

### CIS 1.6 -- Ensure hardware MFA is enabled for the 'root' user account

Verify hardware MFA enforcement in SCPs or organizational policies.

### CIS 1.7 -- Eliminate use of the 'root' user for administrative and daily tasks

Check for SCPs that restrict root user actions:

```hcl
# Look for SCP denying root usage
resource "aws_organizations_policy" {
  content = ... "Deny" ... "root" ...
}
```

### CIS 1.8 -- Ensure IAM password policy requires minimum length of 14 or greater

**What to look for in Terraform:**

```hcl
resource "aws_iam_account_password_policy" {
  minimum_password_length = 14  # Must be >= 14
}
```

### CIS 1.9 -- Ensure IAM password policy prevents password reuse

Check `password_reuse_prevention` is set to 24 or greater.

### CIS 1.10 -- Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password

Look for IAM policies or SCPs enforcing MFA:

```json
{
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

### CIS 1.11 -- Do not setup access keys during initial user setup

Verify no `aws_iam_access_key` resources are created alongside `aws_iam_user` resources.

### CIS 1.12 -- Ensure credentials unused for 45 days or greater are disabled

Check for AWS Config rules or Lambda functions enforcing credential rotation:

```
aws_config_config_rule.*iam-user-unused-credentials-check
max_credential_age
```

### CIS 1.13 -- Ensure there is only one active access key available for any single IAM user

Look for multiple `aws_iam_access_key` resources per user.

### CIS 1.14 -- Ensure access keys are rotated every 90 days or less

Check for Config rules enforcing rotation:

```
access-keys-rotated
maxAccessKeyAge
```

### CIS 1.15 -- Ensure IAM Users receive permissions only through Groups

**Grep patterns:**

```
# BAD: Direct user policy attachment
aws_iam_user_policy_attachment
aws_iam_user_policy

# GOOD: Group-based policy attachment
aws_iam_group_policy_attachment
aws_iam_group_membership
```

### CIS 1.16 -- Ensure IAM policies that allow full "*:*" administrative privileges are not attached

**Critical check -- search for overly permissive policies:**

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

### CIS 1.17 -- Ensure a support role has been created to manage incidents with AWS Support

Check for IAM role with `AWSSupportAccess` managed policy attached.

### CIS 1.18 -- Ensure IAM instance roles are used for AWS resource access from instances

Verify EC2 instances use instance profiles rather than embedded credentials.

### CIS 1.19 -- Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed

Check for certificate management configurations.

### CIS 1.20 -- Ensure that IAM Access Analyzer is enabled for all regions

**Grep patterns:**

```
aws_accessanalyzer_analyzer
type = "ACCOUNT"
```

### CIS 1.21 -- Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments

Check for SSO/Identity Center configuration:

```
aws_ssoadmin_managed_policy_attachment
aws_identitystore
aws_organizations_organization
```

### CIS 1.22 -- Ensure access to AWSCloudShellFullAccess is restricted

Look for policies restricting CloudShell access.

---

## Section 2 -- Storage

Evaluate storage configurations against the selected benchmark version. The legacy v3.0.0 checklist focuses on S3, EBS, RDS, and EFS. For v5.0.0-aware reviews, first confirm whether the selected mapping adds, removes, or remaps controls for additional storage and messaging services before scoring.

### CIS 2.1.1 -- Ensure S3 Bucket Policy is set to deny HTTP requests

**What to look for:**

```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
```

### CIS 2.1.2 -- Ensure MFA Delete is enabled on S3 buckets

Check for `mfa_delete = "Enabled"` in bucket versioning configuration.

### CIS 2.1.3 -- Ensure all data in Amazon S3 has been discovered, classified, and secured when required

Look for Macie configuration:

```
aws_macie2_account
aws_macie2_classification_job
```

### CIS 2.1.4 -- Ensure that S3 Buckets are configured with 'Block public access'

**Critical check:**

```hcl
resource "aws_s3_bucket_public_access_block" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

Also verify account-level public access block:

```
aws_s3_account_public_access_block
```

### CIS 2.2.1 -- Ensure EBS Volume Encryption is Enabled in all Regions

Check for default EBS encryption:

```
aws_ebs_encryption_by_default
enabled = true
```

### CIS 2.3.1 -- Ensure that encryption is enabled for RDS instances

**Grep patterns:**

```hcl
resource "aws_db_instance" {
  storage_encrypted = true  # Must be true
  kms_key_id        = ...   # Should use CMK
}
```

### CIS 2.3.2 -- Ensure Auto Minor Version Upgrade feature is enabled for RDS instances

Check `auto_minor_version_upgrade = true` on all RDS instances.

### CIS 2.3.3 -- Ensure that public access is not given to RDS instance

**Critical check:**

```hcl
# BAD
publicly_accessible = true

# GOOD
publicly_accessible = false
```

### CIS 2.4.1 -- Ensure that encryption is enabled for EFS file systems

Check for EFS encryption configuration:

```
aws_efs_file_system
encrypted = true
```

---

## Section 3 -- Logging

Evaluate logging configurations against the selected benchmark version. For v5.0.0-aware reviews, verify whether the selected mapping introduces service-specific logging controls beyond the legacy CloudTrail, AWS Config, VPC Flow Logs, and S3 object-level logging items.

### CIS 3.1 -- Ensure CloudTrail is enabled in all regions

**Grep patterns:**

```hcl
resource "aws_cloudtrail" {
  is_multi_region_trail = true
  enable_logging        = true
}
```

### CIS 3.2 -- Ensure CloudTrail log file validation is enabled

Check `enable_log_file_validation = true` on CloudTrail trails.

### CIS 3.3 -- Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible

Cross-reference the CloudTrail S3 bucket with public access block configuration.

### CIS 3.4 -- Ensure CloudTrail trails are integrated with CloudWatch Logs

Check for `cloud_watch_logs_group_arn` on CloudTrail resources.

### CIS 3.5 -- Ensure AWS Config is enabled in all regions

**Grep patterns:**

```
aws_config_configuration_recorder
aws_config_delivery_channel
all_supported = true
include_global_resource_types = true
```

### CIS 3.6 -- Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket

Check for `logging` block on the CloudTrail S3 bucket:

```hcl
resource "aws_s3_bucket_logging" {
  bucket        = aws_s3_bucket.cloudtrail.id
  target_bucket = aws_s3_bucket.access_logs.id
}
```

### CIS 3.7 -- Ensure CloudTrail logs are encrypted at rest using KMS CMKs

Check for `kms_key_id` on CloudTrail resources.

### CIS 3.8 -- Ensure rotation for customer-created symmetric CMKs is enabled

**Grep patterns:**

```hcl
resource "aws_kms_key" {
  enable_key_rotation = true  # Must be true
}
```

### CIS 3.9 -- Ensure VPC flow logging is enabled in all VPCs

Check for `aws_flow_log` resources:

```
aws_flow_log
traffic_type = "ALL"
```

### CIS 3.10 -- Ensure that Object-level logging for write events is enabled for S3 buckets

Check CloudTrail data events for S3:

```hcl
event_selector {
  read_write_type = "All"
  data_resource {
    type   = "AWS::S3::Object"
    values = ["arn:aws:s3"]
  }
}
```

### CIS 3.11 -- Ensure that Object-level logging for read events is enabled for S3 buckets

Same as 3.10 -- verify both read and write events are captured.

---

## Section 4 -- Monitoring

Evaluate monitoring and alerting configurations against the selected benchmark version. Keep CloudWatch metric-filter checks version-scoped; do not assume the legacy v3.0.0 monitoring IDs are unchanged in newer mappings.

### CIS 4.1 -- Ensure a log metric filter and alarm exist for unauthorized API calls

For each of CIS 4.1 through 4.15, check for CloudWatch log metric filters and alarms. The pattern is consistent:

```hcl
resource "aws_cloudwatch_log_metric_filter" {
  pattern = "<specific filter pattern>"
  log_group_name = "<cloudtrail log group>"
  metric_transformation { ... }
}

resource "aws_cloudwatch_metric_alarm" {
  alarm_name   = "<descriptive name>"
  metric_name  = "<matching metric>"
  alarm_actions = [<SNS topic ARN>]
}
```

**Required metric filters and alarms (CIS 4.1 through 4.15):**

| CIS ID | Monitoring Target | Filter Pattern Key Elements |
|--------|------------------|-----------------------------|
| 4.1 | Unauthorized API calls | `errorCode = "*UnauthorizedAccess*" \|\| errorCode = "AccessDenied*"` |
| 4.2 | Management Console sign-in without MFA | `eventName = "ConsoleLogin" && additionalEventData.MFAUsed != "Yes"` |
| 4.3 | Usage of 'root' account | `userIdentity.type = "Root" && userIdentity.invokedBy NOT EXISTS` |
| 4.4 | IAM policy changes | `eventName = CreatePolicy \|\| DeletePolicy \|\| AttachRolePolicy ...` |
| 4.5 | CloudTrail configuration changes | `eventName = CreateTrail \|\| UpdateTrail \|\| DeleteTrail \|\| StopLogging` |
| 4.6 | AWS Management Console authentication failures | `eventName = "ConsoleLogin" && errorMessage = "Failed authentication"` |
| 4.7 | Disabling or scheduled deletion of CMKs | `eventSource = kms.amazonaws.com && (DisableKey \|\| ScheduleKeyDeletion)` |
| 4.8 | S3 bucket policy changes | `eventSource = s3.amazonaws.com && (PutBucketAcl \|\| PutBucketPolicy ...)` |
| 4.9 | AWS Config configuration changes | `eventSource = config.amazonaws.com && (StopConfigurationRecorder ...)` |
| 4.10 | Security group changes | `eventName = AuthorizeSecurityGroup* \|\| RevokeSecurityGroup* ...` |
| 4.11 | Network ACL changes | `eventName = CreateNetworkAcl* \|\| DeleteNetworkAcl* ...` |
| 4.12 | Network gateway changes | `eventName = CreateCustomerGateway \|\| AttachInternetGateway ...` |
| 4.13 | Route table changes | `eventName = CreateRoute* \|\| DeleteRoute* \|\| ReplaceRoute* ...` |
| 4.14 | VPC changes | `eventName = CreateVpc \|\| DeleteVpc \|\| ModifyVpcAttribute ...` |
| 4.15 | AWS Organizations changes | `eventSource = organizations.amazonaws.com` |

### CIS 4.16 -- Ensure AWS Security Hub is enabled

**Grep patterns:**

```
aws_securityhub_account
aws_securityhub_standards_subscription
```

---

## Section 5 -- Networking

Evaluate network configurations against the selected benchmark version. The legacy items below cover NACLs, security groups, default security groups, peering route scope, and IMDSv2. For newer mappings, also check whether the selected version adds VPC endpoint, PrivateLink, Network Firewall, EKS, or ECS network controls.

### CIS 5.1 -- Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports

**Grep patterns:**

```hcl
# BAD: NACL allowing SSH/RDP from anywhere
resource "aws_network_acl_rule" {
  cidr_block = "0.0.0.0/0"
  from_port  = 22   # or 3389
  rule_action = "allow"
}
```

### CIS 5.2 -- Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports

**Critical check -- this is one of the most common AWS misconfigurations:**

```hcl
# BAD: Security group allowing SSH from anywhere
resource "aws_security_group_rule" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]  # FAIL
}

# BAD: Security group allowing RDP from anywhere
resource "aws_security_group_rule" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  cidr_blocks = ["0.0.0.0/0"]  # FAIL
}
```

Also check for `::/0` (IPv6 any) on the same ports.

### CIS 5.3 -- Ensure no security groups allow ingress from ::/0 to remote server administration ports

Same evaluation as 5.2 but for IPv6 CIDR `::/0`.

### CIS 5.4 -- Ensure the default security group of every VPC restricts all traffic

**What to look for:**

```hcl
resource "aws_default_security_group" {
  vpc_id = aws_vpc.main.id
  # Should have NO ingress or egress rules (empty = deny all)
}
```

If no `aws_default_security_group` resource is managed, flag this -- the default SG allows all traffic within itself by default.

### CIS 5.5 -- Ensure routing tables for VPC peering are "least access"

Check that VPC peering route tables do not route entire CIDR ranges unnecessarily.

### CIS 5.6 -- Ensure that EC2 Metadata Service only allows IMDSv2

**Critical check:**

```hcl
resource "aws_instance" {
  metadata_options {
    http_tokens = "required"  # Enforces IMDSv2
    http_endpoint = "enabled"
  }
}

# Also check launch templates
resource "aws_launch_template" {
  metadata_options {
    http_tokens = "required"
  }
}
```

---

## Current-Version Expansion Gates

When the selected mapping is v5.0.0 or another current Security Hub CSPM standard, add the following gates before final scoring. These gates are deliberately mapping-aware: use official AWS/CIS mapping evidence for exact control IDs instead of inventing IDs from service names.

### Compute and Runtime Services

| Area | Evidence to Search | Scoring Guidance |
|------|--------------------|------------------|
| EC2 runtime metadata | `metadata_options`, `http_tokens`, launch templates, Auto Scaling launch configurations | Score only against the selected mapping. If the environment uses launch templates but only instances were checked, mark incomplete evidence. |
| Lambda | `aws_lambda_function`, `aws_lambda_permission`, `aws_lambda_function_url`, runtime versions, environment encryption, VPC config, logging config | Require mapping evidence before assigning a CIS ID. Missing runtime/logging/VPC evidence is `not_evaluable_from_supplied_evidence` when only partial IaC is supplied. |
| ECS | `aws_ecs_task_definition`, task execution roles, log configuration, network mode, secrets injection, service discovery | Distinguish task execution role evidence from application task role evidence. |
| EKS | `aws_eks_cluster`, control plane logging, public endpoint access, node security groups, IAM roles for service accounts | Do not treat generic Kubernetes YAML as proof of AWS managed-control compliance without EKS cluster evidence. |

### Application and Event Services

| Area | Evidence to Search | Scoring Guidance |
|------|--------------------|------------------|
| API Gateway / AppSync | `aws_api_gateway_*`, `aws_apigatewayv2_*`, `aws_appsync_graphql_api`, access logging, auth type, WAF association | Record whether the evidence comes from IaC, Security Hub, or manual screenshots/export. |
| SQS / SNS | `aws_sqs_queue`, `aws_sns_topic`, encryption, queue/topic policy, dead-letter queue evidence | Separate encryption posture from cross-account policy exposure. |
| Step Functions | `aws_sfn_state_machine`, logging configuration, tracing, encryption, execution history retention | Some controls may be manual or unsupported in Security Hub; mark status explicitly. |
| EventBridge | `aws_cloudwatch_event_bus`, `aws_cloudwatch_event_rule`, event bus policy, archive/replay settings | Watch for cross-account event bus policies and missing owner context. |

### Version-Mapping Crosswalk

For every control that appears in the final report, add a row like:

```
control_id: CIS <selected-version-id>
legacy_ids: [CIS v3.0.0 <old-id>, ...]
security_hub_control_id: <Security Hub control, if available>
support_status: current | legacy | removed | unsupported | manual | not_evaluable_from_supplied_evidence
mapping_source: <AWS Security Hub CSPM version comparison / CIS material / internal crosswalk>
evidence_source: <file, Security Hub finding, or manual artifact>
assessment_status: Pass | Fail | Not Applicable | Not Evaluable
```

Do not include removed, unsupported, or legacy-only controls in the current benchmark denominator. Keep them in a migration appendix when they are useful for explaining why a historical report differs from the current Security Hub score.
