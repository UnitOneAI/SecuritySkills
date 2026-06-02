# Vulnerable: cloud/SaaS export lacks provenance and repeatability

```yaml
cloud_provider: AWS
account_id: missing
region: us-east-1
resource: i-1234567890abcdef
evidence:
  ebs_snapshot_id: missing
  kms_key_state: unknown
  cloudtrail_digest_validation: not_checked
  object_lock: missing
  api_query: missing
  pagination_tokens: missing
  collector_identity: unknown
saas_export:
  export_job_id: missing
  api_version: missing
  timezone: local string
```

Expected assessment: mark the cloud/SaaS evidence as incomplete or Not
Evaluable. Snapshot/export IDs, account/region, KMS state, retention, API query,
pagination, collector identity, and timestamp normalization are required for
repeatable cloud forensic evidence.
