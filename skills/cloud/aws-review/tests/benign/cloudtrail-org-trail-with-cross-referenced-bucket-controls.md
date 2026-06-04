---
name: cloudtrail-org-trail-with-cross-referenced-bucket-controls
expected: benign
category: CIS-3-Logging
cwe: CWE-778
---

# Benign AWS Fixture: Organization Trail With Cross-Referenced Controls

This fixture should not be flagged for the CloudTrail integrity chain. It uses
an organization trail and shows the linked bucket controls, KMS key, CloudWatch
Logs integration, and S3 object data events needed to support the CIS 3.x pass
decision.

```hcl
resource "aws_s3_bucket" "org_cloudtrail" {
  bucket = "example-org-cloudtrail-logs"
}

resource "aws_s3_bucket_public_access_block" "org_cloudtrail" {
  bucket                  = aws_s3_bucket.org_cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "org_cloudtrail" {
  description         = "Organization CloudTrail logs"
  enable_key_rotation = true
}

resource "aws_cloudwatch_log_group" "org_cloudtrail" {
  name = "/aws/cloudtrail/org"
}

resource "aws_iam_role" "org_cloudtrail_logs" {
  name = "org-cloudtrail-cloudwatch-logs"
}

resource "aws_cloudtrail" "org" {
  name                          = "organization"
  s3_bucket_name                = aws_s3_bucket.org_cloudtrail.id
  enable_logging                = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.org_cloudtrail.arn
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.org_cloudtrail.arn
  cloud_watch_logs_role_arn     = aws_iam_role.org_cloudtrail_logs.arn
  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::finance-data/", "arn:aws:s3:::customer-data/"]
    }
  }
}

resource "aws_s3_bucket_policy" "org_cloudtrail" {
  bucket = aws_s3_bucket.org_cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.org_cloudtrail.arn}/*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AllowCloudTrailWriteFromOrgTrail"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.org_cloudtrail.arn}/AWSLogs/o-exampleorgid/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = aws_cloudtrail.org.arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
```

## Expected Safe Evidence

| Evidence Gate | Fixture State |
|---|---|
| Trail coverage | Organization, multi-region, and enabled |
| Log validation | Enabled on the organization trail |
| Log bucket controls | Public access block and source-constrained CloudTrail write policy present |
| KMS protection | Referenced rotating KMS key present |
| CloudWatch integration | Log group and role ARN linked |
| Object-level data events | S3 read/write data selectors present |

The skill should accept an organization trail only when the linked evidence
chain is present, not merely because `is_organization_trail = true` exists.
