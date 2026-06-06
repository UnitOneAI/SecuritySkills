# S3 Object Ownership Edge Cases

These fixtures verify that `aws-review` records S3 Object Ownership separately from Block Public Access before judging ACL exposure or bucket-owner control.

```yaml
case_id: S3-OWN-01
title: BucketOwnerEnforced disables ACLs with bucket and account public access blocks
bucket: prod-logs
evidence:
  terraform:
    ownership_controls: BucketOwnerEnforced
    bucket_public_access_block:
      block_public_acls: true
      ignore_public_acls: true
      block_public_policy: true
      restrict_public_buckets: true
    account_public_access_block: present
  aws_cli:
    get_bucket_ownership_controls: BucketOwnerEnforced
expected_classification:
  status: Pass
  reason: "ACLs are disabled and both bucket/account public access block evidence are present."
```

```yaml
case_id: S3-OWN-02
title: ObjectWriter remains enabled despite Block Public Access
bucket: partner-uploads
evidence:
  terraform:
    ownership_controls: ObjectWriter
    bucket_public_access_block:
      block_public_acls: true
      ignore_public_acls: true
  acl_review: missing
  migration_plan: missing
expected_classification:
  status: Fail
  severity: Medium
  reason: "Block Public Access does not disable ACLs or prove bucket-owner control when ObjectWriter is configured."
```

```yaml
case_id: S3-OWN-03
title: BucketOwnerPreferred lacks bucket-owner-full-control upload policy
bucket: cross-account-ingest
evidence:
  terraform:
    ownership_controls: BucketOwnerPreferred
  bucket_policy:
    requires_bucket_owner_full_control: false
  client_upload_contract: missing
expected_classification:
  status: Fail
  severity: Medium
  reason: "Cross-account writers may create objects the bucket owner does not fully control."
```

```yaml
case_id: S3-OWN-04
title: Imported legacy bucket has no ownership-controls evidence
bucket: legacy-archive
evidence:
  terraform:
    aws_s3_bucket: imported
    ownership_controls: missing
  cloudformation:
    ownership_controls: missing
  aws_cli:
    get_bucket_ownership_controls: missing
  new_bucket_default_claim: unproven
expected_classification:
  status: Not Evaluable
  reason: "Existing or imported buckets need explicit ownership-controls evidence; new-bucket defaults cannot be assumed."
```

```yaml
case_id: S3-OWN-05
title: SCP guardrail plus per-bucket CLI evidence proves enforced ownership
bucket: app-artifacts
evidence:
  scp_guardrail:
    condition_key: s3:x-amz-object-ownership
    required_value: BucketOwnerEnforced
  aws_cli:
    get_bucket_ownership_controls: BucketOwnerEnforced
  bucket_public_access_block: complete
expected_classification:
  status: Pass
  reason: "Guardrail covers new buckets and CLI evidence proves the reviewed bucket is ACL-disabled."
```

```yaml
case_id: S3-OWN-06
title: Static website ACL exception is documented and bounded
bucket: public-website-assets
evidence:
  ownership_controls: BucketOwnerPreferred
  public_access_block:
    block_public_policy: false
    restrict_public_buckets: false
  exception:
    owner: web-platform
    business_reason: static website hosting
    bucket_policy_reviewed: true
    writer_inventory: documented
    migration_target_date: "2026-09-30"
expected_classification:
  status: Documented exception
  severity: Informational
  reason: "ACL-dependent public website use is documented with ownership, policy, and migration evidence."
```

```yaml
case_id: S3-OWN-07
title: Historical ACL resource should not create a false positive when ACLs are disabled
bucket: audit-exports
evidence:
  terraform:
    aws_s3_bucket_acl: present
    ownership_controls: BucketOwnerEnforced
  aws_behavior:
    acl_put_error: AccessControlListNotSupported
  bucket_policy_controls_access: true
expected_classification:
  status: Pass
  reason: "BucketOwnerEnforced makes historical ACL resources non-authoritative; policy/IAM controls access."
```
