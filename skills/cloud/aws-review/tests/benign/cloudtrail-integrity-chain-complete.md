---
name: cloudtrail-integrity-chain-complete
expected: benign
category: CIS-3-Logging
cwe: CWE-778
---

# Benign AWS Fixture: CloudTrail Integrity Chain Complete

This fixture should not be flagged for CloudTrail integrity gaps. The trail is
multi-region, validates log files, writes to a protected S3 bucket, uses a KMS
key, integrates with CloudWatch Logs, and captures S3 object data events.

```hcl
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "example-cloudtrail-logs"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AllowCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/123456789012/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = aws_cloudtrail.main.arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_kms_key" "cloudtrail" {
  description         = "CloudTrail log encryption"
  enable_key_rotation = true
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "/aws/cloudtrail/main"
}

resource "aws_iam_role" "cloudtrail_logs" {
  name = "cloudtrail-cloudwatch-logs"
}

resource "aws_cloudtrail" "main" {
  name                          = "main"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn
  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::sensitive-bucket/"]
    }
  }
}
```

## Expected Safe Evidence

| Evidence Gate | Fixture State |
|---|---|
| Trail coverage | Multi-region and enabled |
| Log validation | Enabled on the same trail |
| Log bucket controls | Public access block and CloudTrail/TLS bucket policy present |
| KMS protection | `kms_key_id` references a rotating KMS key |
| CloudWatch integration | Log group and role ARN linked |
| Object-level data events | S3 read/write object selector present |

The skill should treat the linked evidence chain as sufficient for the reviewed
CloudTrail integrity controls.
