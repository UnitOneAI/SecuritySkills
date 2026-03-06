# IaC Security -- Tool-Specific Rule Sets and Detection Patterns

This file contains the detailed tool-specific rule sets, detection patterns, and remediation examples for the Infrastructure as Code Security Review skill. See [SKILL.md](SKILL.md) for the main skill definition, process overview, and output format.

---

## Hardcoded Secrets Detection

Scan for credentials, tokens, and keys embedded directly in IaC files. This is the highest-priority check because hardcoded secrets in version control are immediately exploitable.

### Detection Patterns

**Grep for common secret patterns across all IaC files:**

```
# AWS credentials
AKIA[0-9A-Z]{16}
aws_secret_access_key
aws_access_key_id

# Azure credentials
client_secret
tenant_id.*secret
password\s*=

# GCP credentials
private_key_id
private_key.*BEGIN

# Generic secrets
api_key\s*=
api_secret
secret_key\s*=
token\s*=\s*"[^"]{8,}"
password\s*=\s*"[^"]{1,}"
private_key\s*=

# Database credentials
db_password
database_password
master_password
admin_password

# Connection strings with embedded credentials
mongodb\+srv://[^:]+:[^@]+@
postgres://[^:]+:[^@]+@
mysql://[^:]+:[^@]+@
amqp://[^:]+:[^@]+@
redis://:[^@]+@
```

**Checkov equivalent rules:**
- CKV_SECRET_1 through CKV_SECRET_80 (various secret patterns)
- CKV_AWS_41: Ensure RDS instance credentials are not in plaintext

**tfsec equivalent rules:**
- general-secrets-sensitive-in-variable
- general-secrets-sensitive-in-attribute

**Severity:** Critical for any confirmed hardcoded secret.

**Remediation pattern:**

```hcl
# BAD: Hardcoded password
resource "aws_db_instance" "example" {
  password = "SuperSecret123!"
}

# GOOD: Reference from secrets manager or variable
resource "aws_db_instance" "example" {
  password = data.aws_secretsmanager_secret_version.db.secret_string
}

# GOOD: Variable with sensitive flag
variable "db_password" {
  type      = string
  sensitive = true
}
```

---

## Public Exposure Analysis

Identify resources that are unintentionally exposed to the public internet.

### Storage -- Public Buckets and Containers

**Terraform (AWS):**

```hcl
# BAD: Missing public access block
resource "aws_s3_bucket" "example" { }

# BAD: Public ACL
resource "aws_s3_bucket_acl" "example" {
  acl = "public-read"      # FAIL
  acl = "public-read-write" # CRITICAL FAIL
}
```

**Checkov:** CKV_AWS_19, CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56
**tfsec:** aws-s3-no-public-access-with-acl, aws-s3-enable-bucket-encryption

**CloudFormation:**

```yaml
# BAD: Public bucket
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead  # FAIL
```

**KICS:** 3406e4d3 (S3 bucket with public ACL)

**Terraform (Azure):**

```hcl
# BAD: Public blob access
resource "azurerm_storage_account" "example" {
  allow_nested_items_to_be_public = true  # FAIL
}
```

**Terraform (GCP):**

```hcl
# BAD: Public GCS bucket
resource "google_storage_bucket_iam_member" "example" {
  member = "allUsers"  # FAIL
}
```

### Databases -- Public Accessibility

```hcl
# BAD: Public RDS
resource "aws_db_instance" "example" {
  publicly_accessible = true  # FAIL
}

# BAD: Public Azure SQL
resource "azurerm_mssql_firewall_rule" "example" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"  # FAIL
}

# BAD: Public Cloud SQL
resource "google_sql_database_instance" "example" {
  settings {
    ip_configuration {
      authorized_networks {
        value = "0.0.0.0/0"  # FAIL
      }
    }
  }
}
```

**Checkov:** CKV_AWS_17 (RDS public access), CKV_AZURE_11 (SQL firewall)
**tfsec:** aws-rds-no-public-db-access

### Compute -- Public IP Assignment

```hcl
# Check for unintended public IPs on compute instances
associate_public_ip_address = true  # Verify this is intentional

# GCP: access_config block assigns public IP
network_interface {
  access_config { }  # Assigns ephemeral public IP
}
```

### Security Groups / Firewall Rules -- Unrestricted Ingress

```hcl
# BAD: Unrestricted SSH/RDP
resource "aws_security_group_rule" "example" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]  # FAIL
}

# BAD: Unrestricted all traffic
resource "aws_security_group_rule" "example" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  cidr_blocks = ["0.0.0.0/0"]  # CRITICAL FAIL
}
```

**Checkov:** CKV_AWS_24 (SSH from 0.0.0.0/0), CKV_AWS_25 (RDP from 0.0.0.0/0)
**tfsec:** aws-vpc-no-public-ingress-sgr

---

## Encryption Gap Analysis

Verify that encryption at rest and in transit is enabled for all applicable resources.

### Encryption at Rest

**Resources that must have encryption enabled:**

| Resource | Terraform Attribute | Checkov Rule |
|----------|-------------------|--------------|
| AWS S3 bucket | `server_side_encryption_configuration` | CKV_AWS_19 |
| AWS EBS volume | `encrypted = true` | CKV_AWS_3 |
| AWS RDS instance | `storage_encrypted = true` | CKV_AWS_16 |
| AWS EFS | `encrypted = true` | CKV_AWS_42 |
| AWS SNS topic | `kms_master_key_id` | CKV_AWS_26 |
| AWS SQS queue | `kms_master_key_id` | CKV_AWS_27 |
| AWS DynamoDB table | `server_side_encryption { enabled = true }` | CKV_AWS_28 |
| AWS CloudWatch log group | `kms_key_id` | CKV_AWS_158 |
| Azure Storage Account | `infrastructure_encryption_enabled` | CKV_AZURE_43 |
| Azure SQL Database | `transparent_data_encryption_enabled` | CKV_AZURE_24 |
| Azure VM OS Disk | `disk_encryption_set_id` | CKV_AZURE_2 |
| GCP Compute Disk | `disk_encryption_key` | CKV_GCP_37 |
| GCP BigQuery Dataset | `default_encryption_configuration` | CKV_GCP_81 |

**Grep patterns for missing encryption:**

```
# AWS: Resources without encryption
resource "aws_ebs_volume".*{
  # Check for absence of: encrypted = true

resource "aws_db_instance".*{
  # Check for absence of: storage_encrypted = true

resource "aws_s3_bucket".*{
  # Check for absence of server_side_encryption_configuration
```

### Encryption in Transit

```hcl
# AWS: Enforce HTTPS on S3
resource "aws_s3_bucket_policy" "example" {
  # Must contain aws:SecureTransport condition
}

# Azure: HTTPS only
resource "azurerm_storage_account" "example" {
  enable_https_traffic_only = true  # Must be true
  min_tls_version           = "TLS1_2"
}

# GCP: Cloud SQL SSL
resource "google_sql_database_instance" "example" {
  settings {
    ip_configuration {
      require_ssl = true
    }
  }
}
```

### Customer-Managed Keys (CMK) vs. Provider-Managed Keys

Check whether sensitive resources use CMKs for defense-in-depth:

```hcl
# Preferred: CMK encryption
kms_key_id = aws_kms_key.example.arn
kms_key_name = google_kms_crypto_key.example.id
key_vault_key_id = azurerm_key_vault_key.example.id
```

**tfsec:** aws-s3-encryption-customer-key, aws-rds-encrypt-instance-storage-data

---

## IAM and Access Control Review

Evaluate IAM policies and role definitions for overly permissive access.

### Overly Permissive Policies

```json
// BAD: Full admin access
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}

// BAD: Wildcard actions on specific service
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

**Checkov:** CKV_AWS_1 (IAM policy with full admin), CKV_AWS_62 (IAM policy with wildcard resource)
**tfsec:** aws-iam-no-policy-wildcards

### Cross-Account and Public Access

```json
// BAD: Public principal
{
  "Principal": "*",
  "Effect": "Allow"
}

// BAD: Unrestricted cross-account
{
  "Principal": { "AWS": "*" },
  "Effect": "Allow"
}
```

### Service-Linked Role Misuse

Check for roles with `sts:AssumeRole` that have overly broad trust policies.

### Missing Conditions

IAM policies granting sensitive access should include conditions (MFA, source IP, time-based):

```json
// GOOD: Condition-based access
{
  "Condition": {
    "Bool": { "aws:MultiFactorAuthPresent": "true" },
    "IpAddress": { "aws:SourceIp": "203.0.113.0/24" }
  }
}
```

---

## Logging and Monitoring Gaps

Verify that resources have appropriate logging and monitoring enabled.

**Required logging configurations:**

| Resource | Logging Mechanism | Checkov Rule |
|----------|------------------|--------------|
| AWS S3 bucket | Access logging or CloudTrail data events | CKV_AWS_18 |
| AWS CloudTrail | Multi-region, log validation, encryption | CKV_AWS_35, CKV_AWS_36 |
| AWS VPC | Flow logs | CKV_AWS_9 |
| AWS ELB/ALB | Access logging | CKV_AWS_91, CKV_AWS_92 |
| AWS API Gateway | Execution logging | CKV_AWS_73 |
| Azure NSG | Flow logs | CKV_AZURE_12 |
| Azure Key Vault | Diagnostic settings | CKV_AZURE_110 |
| GCP VPC subnet | VPC flow logs | CKV_GCP_26 |
| GCP Cloud SQL | Database flags for logging | CKV_GCP_51, CKV_GCP_52 |

---

## Network Security Review

Evaluate network architecture for security weaknesses.

### Network Segmentation

```hcl
# Verify separate subnets for different tiers
# Public subnets: load balancers, bastion hosts only
# Private subnets: application servers, databases
# Check for resources in public subnets that should be private
```

### Default Security Groups / Firewall Rules

```hcl
# AWS: Default SG should deny all
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # No ingress or egress rules
}

# GCP: Default network should not exist
# Check for google_compute_network named "default"
```

### Egress Controls

```hcl
# Check for unrestricted egress
resource "aws_security_group_rule" "example" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]  # Review: is unrestricted egress intentional?
}
```

---

## Supply Chain Integrity (SLSA Alignment)

Evaluate how IaC modules are sourced and whether the IaC supply chain has integrity controls.

### Module Source Pinning

```hcl
# BAD: Unpinned module from registry
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"  # No version pin
}

# BAD: Branch reference (mutable)
module "vpc" {
  source = "git::https://github.com/org/modules.git//vpc?ref=main"
}

# GOOD: Pinned to specific version
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}

# BEST: Pinned to commit SHA
module "vpc" {
  source = "git::https://github.com/org/modules.git//vpc?ref=abc123def456"
}
```

**Checkov:** CKV_TF_1 (module source pinning)

### Provider Version Pinning

```hcl
# BAD: Unpinned provider
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

# GOOD: Pinned provider with constraints
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
```

### State File Security

```hcl
# Check backend configuration for security
terraform {
  backend "s3" {
    bucket         = "terraform-state"
    encrypt        = true          # Must be true
    dynamodb_table = "tf-locks"    # State locking required
    # Should use separate, restricted IAM credentials
  }
}

# BAD: Local state (no encryption, no locking)
terraform {
  backend "local" { }
}
```

**Checkov:** CKV_AWS_145 (S3 backend encryption)

### Lock File Presence

Verify `.terraform.lock.hcl` exists and is committed:

```
# Check for lock file
.terraform.lock.hcl
```

---

## Resource Hardening

Check for resource-specific hardening configurations.

### Compute Hardening

```hcl
# AWS: IMDSv2 enforcement
resource "aws_instance" "example" {
  metadata_options {
    http_tokens = "required"  # Enforces IMDSv2
  }
}

# AWS: EBS optimization
resource "aws_instance" "example" {
  ebs_optimized = true
}

# GCP: Shielded VM
resource "google_compute_instance" "example" {
  shielded_instance_config {
    enable_secure_boot = true
    enable_vtpm        = true
  }
}
```

**Checkov:** CKV_AWS_79 (IMDSv2), CKV_GCP_39 (Shielded VM)

### Container and Serverless Hardening

```hcl
# AWS Lambda: Reserved concurrency to prevent runaway
resource "aws_lambda_function" "example" {
  reserved_concurrent_executions = 100

  # VPC configuration for network isolation
  vpc_config {
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  # Environment encryption
  kms_key_arn = aws_kms_key.lambda.arn
}

# ECS: Non-privileged containers
resource "aws_ecs_task_definition" "example" {
  container_definitions = jsonencode([{
    privileged = false  # Must be false
    readonlyRootFilesystem = true
    user = "1000:1000"  # Non-root
  }])
}
```

### Backup and Recovery

```hcl
# Verify backup configurations exist for critical resources
resource "aws_db_instance" "example" {
  backup_retention_period = 7   # Must be > 0
  deletion_protection     = true
}

# Azure: Soft delete on Key Vault
resource "azurerm_key_vault" "example" {
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
}
```
