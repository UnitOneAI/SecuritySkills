# IaC Scanner Rule Mapping Reference

Extracted from [tool-rules.md](../tool-rules.md) and [SKILL.md](../SKILL.md). This file consolidates the Checkov, tfsec, and KICS rule equivalents applied by the IaC Security Review skill.

---

## Quick Reference Table

| Tool | Rule ID | Description | Domain |
|------|---------|-------------|--------|
| Checkov | CKV_AWS_1 | IAM policy with full admin privileges | IAM |
| Checkov | CKV_AWS_3 | EBS volume encryption | Encryption |
| Checkov | CKV_AWS_9 | VPC flow logs | Logging |
| Checkov | CKV_AWS_16 | RDS instance encryption | Encryption |
| Checkov | CKV_AWS_17 | RDS not publicly accessible | Public Exposure |
| Checkov | CKV_AWS_18 | S3 access logging | Logging |
| Checkov | CKV_AWS_19 | S3 server-side encryption | Encryption |
| Checkov | CKV_AWS_24 | No SSH from 0.0.0.0/0 | Network Security |
| Checkov | CKV_AWS_25 | No RDP from 0.0.0.0/0 | Network Security |
| Checkov | CKV_AWS_26 | SNS topic encryption | Encryption |
| Checkov | CKV_AWS_27 | SQS queue encryption | Encryption |
| Checkov | CKV_AWS_28 | DynamoDB table encryption | Encryption |
| Checkov | CKV_AWS_35 | CloudTrail log validation | Logging |
| Checkov | CKV_AWS_36 | CloudTrail multi-region | Logging |
| Checkov | CKV_AWS_41 | RDS instance credentials not in plaintext | Secrets |
| Checkov | CKV_AWS_42 | EFS encryption | Encryption |
| Checkov | CKV_AWS_53 | S3 block public ACLs | Public Exposure |
| Checkov | CKV_AWS_54 | S3 block public policy | Public Exposure |
| Checkov | CKV_AWS_55 | S3 ignore public ACLs | Public Exposure |
| Checkov | CKV_AWS_56 | S3 restrict public buckets | Public Exposure |
| Checkov | CKV_AWS_62 | IAM policy with wildcard resource | IAM |
| Checkov | CKV_AWS_73 | API Gateway execution logging | Logging |
| Checkov | CKV_AWS_79 | IMDSv2 required | Resource Hardening |
| Checkov | CKV_AWS_91 | ELB access logging | Logging |
| Checkov | CKV_AWS_92 | ALB access logging | Logging |
| Checkov | CKV_AWS_145 | S3 backend encryption for state | Supply Chain |
| Checkov | CKV_AWS_158 | CloudWatch log group encryption | Encryption |
| Checkov | CKV_SECRET_1-80 | Hardcoded secret patterns | Secrets |
| Checkov | CKV_TF_1 | Module source pinning | Supply Chain |
| Checkov | CKV_AZURE_2 | Azure VM OS disk encryption | Encryption |
| Checkov | CKV_AZURE_11 | Azure SQL firewall rules | Public Exposure |
| Checkov | CKV_AZURE_12 | Azure NSG flow logs | Logging |
| Checkov | CKV_AZURE_24 | Azure SQL TDE | Encryption |
| Checkov | CKV_AZURE_43 | Azure Storage infrastructure encryption | Encryption |
| Checkov | CKV_AZURE_110 | Azure Key Vault diagnostics | Logging |
| Checkov | CKV_GCP_26 | GCP VPC subnet flow logs | Logging |
| Checkov | CKV_GCP_37 | GCP compute disk encryption | Encryption |
| Checkov | CKV_GCP_39 | GCP Shielded VM | Resource Hardening |
| Checkov | CKV_GCP_51 | GCP Cloud SQL logging (checkpoints) | Logging |
| Checkov | CKV_GCP_52 | GCP Cloud SQL logging (connections) | Logging |
| Checkov | CKV_GCP_81 | GCP BigQuery dataset encryption | Encryption |
| tfsec | aws-iam-no-policy-wildcards | No wildcard IAM policies | IAM |
| tfsec | aws-s3-no-public-access-with-acl | No public S3 ACL | Public Exposure |
| tfsec | aws-s3-enable-bucket-encryption | S3 bucket encryption | Encryption |
| tfsec | aws-s3-encryption-customer-key | S3 CMK encryption | Encryption |
| tfsec | aws-rds-no-public-db-access | No public RDS | Public Exposure |
| tfsec | aws-rds-encrypt-instance-storage-data | RDS encryption | Encryption |
| tfsec | aws-vpc-no-public-ingress-sgr | No public SG ingress | Network Security |
| tfsec | general-secrets-sensitive-in-variable | Secrets in variables | Secrets |
| tfsec | general-secrets-sensitive-in-attribute | Secrets in attributes | Secrets |
| KICS | 3406e4d3 | S3 public ACL | Public Exposure |
| KICS | 5b4f3042 | Unrestricted security group | Network Security |

---

## Domain-Grouped Mapping

### Secrets Management
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_SECRET_1-80 | Various hardcoded secret patterns |
| Checkov | CKV_AWS_41 | RDS credentials not in plaintext |
| tfsec | general-secrets-sensitive-in-variable | Sensitive data in variables |
| tfsec | general-secrets-sensitive-in-attribute | Sensitive data in attributes |

### Public Exposure
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_AWS_17 | RDS publicly accessible |
| Checkov | CKV_AWS_53-56 | S3 public access block settings |
| Checkov | CKV_AZURE_11 | Azure SQL firewall open |
| tfsec | aws-s3-no-public-access-with-acl | S3 public ACL |
| tfsec | aws-rds-no-public-db-access | RDS public access |
| KICS | 3406e4d3 | S3 public ACL |

### Encryption
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_AWS_3 | EBS encryption |
| Checkov | CKV_AWS_16 | RDS encryption |
| Checkov | CKV_AWS_19 | S3 encryption |
| Checkov | CKV_AWS_26-28 | SNS/SQS/DynamoDB encryption |
| Checkov | CKV_AWS_42 | EFS encryption |
| Checkov | CKV_AWS_158 | CloudWatch log group encryption |
| Checkov | CKV_AZURE_2 | Azure VM disk encryption |
| Checkov | CKV_AZURE_24 | Azure SQL TDE |
| Checkov | CKV_AZURE_43 | Azure Storage infrastructure encryption |
| Checkov | CKV_GCP_37 | GCP disk encryption |
| Checkov | CKV_GCP_81 | GCP BigQuery encryption |
| tfsec | aws-s3-encryption-customer-key | S3 CMK |
| tfsec | aws-rds-encrypt-instance-storage-data | RDS storage encryption |

### Network Security
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_AWS_24 | SSH from 0.0.0.0/0 |
| Checkov | CKV_AWS_25 | RDP from 0.0.0.0/0 |
| tfsec | aws-vpc-no-public-ingress-sgr | Public SG ingress |
| KICS | 5b4f3042 | Unrestricted security group |

### Logging
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_AWS_9 | VPC flow logs |
| Checkov | CKV_AWS_18 | S3 access logging |
| Checkov | CKV_AWS_35-36 | CloudTrail configuration |
| Checkov | CKV_AWS_73 | API Gateway logging |
| Checkov | CKV_AWS_91-92 | Load balancer logging |
| Checkov | CKV_AZURE_12 | NSG flow logs |
| Checkov | CKV_AZURE_110 | Key Vault diagnostics |
| Checkov | CKV_GCP_26 | VPC subnet flow logs |
| Checkov | CKV_GCP_51-52 | Cloud SQL logging |

### IAM & Access Control
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_AWS_1 | Full admin policy |
| Checkov | CKV_AWS_62 | Wildcard resource policy |
| tfsec | aws-iam-no-policy-wildcards | Wildcard IAM |

### Supply Chain
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_TF_1 | Module source pinning |
| Checkov | CKV_AWS_145 | State backend encryption |

### Resource Hardening
| Tool | Rule | Description |
|------|------|-------------|
| Checkov | CKV_AWS_79 | IMDSv2 enforcement |
| Checkov | CKV_GCP_39 | Shielded VM |
