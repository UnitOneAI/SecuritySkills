---
name: cloudtrail-no-log-validation-or-kms
expected: vulnerable
category: CIS-3-Logging
cwe: CWE-778
---

# Vulnerable AWS Fixture: CloudTrail Exists Without Integrity Chain

This fixture should be flagged. The trail is enabled and multi-region, but it
lacks log file validation, KMS encryption, CloudWatch Logs integration, and
linked S3 bucket controls.

```hcl
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "example-cloudtrail-logs"
}

resource "aws_cloudtrail" "main" {
  name                  = "main"
  s3_bucket_name        = aws_s3_bucket.cloudtrail.id
  enable_logging        = true
  is_multi_region_trail = true
}
```

## Expected Finding Evidence

| Evidence Gate | Fixture State |
|---|---|
| Trail coverage | Present |
| Log validation | Missing |
| Log bucket controls | Bucket exists, but public access block and policy evidence are missing |
| KMS protection | Missing `kms_key_id` |
| CloudWatch integration | Missing |
| Object-level data events | Missing |

The skill should not mark CIS 3.x logging controls as fully passing based only
on the standalone trail resource.
