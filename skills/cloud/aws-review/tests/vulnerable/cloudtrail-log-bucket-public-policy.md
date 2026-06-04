---
name: cloudtrail-log-bucket-public-policy
expected: vulnerable
category: CIS-3-Logging
cwe: CWE-532
---

# Vulnerable AWS Fixture: CloudTrail Log Bucket Policy Is Public

This fixture should be flagged even though the CloudTrail resource has
multi-region logging, log file validation, CloudWatch integration, and KMS
encryption. The linked log bucket policy still grants public read access to the
CloudTrail log prefix.

```hcl
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "example-cloudtrail-logs"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadCloudTrailLogs"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/123456789012/*"
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                       = "main"
  s3_bucket_name             = aws_s3_bucket.cloudtrail.id
  enable_logging             = true
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.cloudtrail.arn
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_logs.arn
}
```

## Expected Finding Evidence

| Evidence Gate | Fixture State |
|---|---|
| Trail coverage | Present |
| Log validation | Present |
| Log bucket controls | Public policy and disabled public-policy block |
| KMS protection | Present |
| CloudWatch integration | Present |

The skill should report the bucket policy/public access controls as a CloudTrail
logging-chain failure instead of passing the trail based on CloudTrail fields
alone.
