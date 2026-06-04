# Dataset Rights and Deletion Lineage Test Cases

These fixtures calibrate the `model-supply-chain` review for dataset authorization, deletion propagation, and false-positive handling when raw sensitive data is intentionally not retained.

## Vulnerable: secure snapshot with incompatible training rights

```text
dataset_manifest:
  id: partner-support-v3
  source: partner helpdesk export
  version: 2026-05-30
  transform_digest: sha256:1111...
  pii_filter: applied
  write_access: restricted
  license_snapshot: missing
  data_sharing_agreement:
    expiry: 2026-05-01
    covered_use: "support analytics only"
  model_use: "commercial fine-tuning for customer support assistant"
```

Expected finding:

- Category: Training Data
- Severity: High
- Evidence: the dataset is versioned and filtered, but the agreement expired before assembly and the covered use excludes commercial fine-tuning.
- Recommendation: block new training runs until a current license/terms snapshot and covered-use approval are attached to the dataset manifest.

## Vulnerable: deletion stops at the app database

```text
deletion_request:
  user_id: usr_1842
  received: 2026-06-01
  app_database_status: deleted

training_artifacts:
  fine_tune_snapshot: support-sft-2026-05
  adapter: support-lora-v8
  embedding_store: kb-support-v12
  retraining_queue: not checked
  deletion_receipt: app-db-only
```

Expected finding:

- Category: Training Data
- Severity: High
- Evidence: the deletion request has no traceable status for fine-tuning snapshots, adapters, embedding stores, or retraining queues.
- Recommendation: add deletion propagation records, artifact retirement criteria, and retraining cutoffs before accepting deletion compliance.

## Benign: raw PII is not retained but lineage is auditable

```text
dataset_manifest:
  id: deidentified-feedback-v4
  source: product feedback export
  version: 2026-05-30
  source_license_snapshot: recorded
  consent_basis: product-improvement and model-training opt-in
  retention_class: "raw PII retention 0 days after filtering"
  deletion_requests: applied before train run
  transform_digest: sha256:2222...
  filtered_snapshot_hash: sha256:3333...
  last_rights_review: 2026-06-01
  downstream_artifacts:
    adapter: not trained until post-deletion snapshot
    retraining_queue: deletion watermark enforced
```

Expected result:

- No finding solely for missing raw sensitive data.
- The reviewer can audit source, rights, deletion state, transform reproducibility, and downstream deletion propagation without retaining raw PII.
