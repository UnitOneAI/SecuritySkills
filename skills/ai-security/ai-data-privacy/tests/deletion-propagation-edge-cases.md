# Deletion Propagation Edge Cases

These fixtures validate AI data privacy review behavior for deletion, erasure, consent withdrawal, and retention expiry across AI-derived stores.

## Case 1: DSAR Deletes Primary User Only

```yaml
dsar:
  endpoint: DELETE /privacy/users/{id}
  deletes:
    - users
    - profiles
  not_mapped:
    - conversation_logs
    - prompt_logs
    - vector_chunks
    - embeddings
    - analytics_exports
```

**Expected result:** High severity finding.

**Reason:** The workflow deletes primary records but cannot prove removal from AI-derived stores that may still contain personal data.

## Case 2: Source Document Deleted, Embeddings Remain Searchable

```yaml
rag:
  source_document:
    id: doc-123
    deleted: true
  vector_store:
    chunks:
      - id: chunk-123-a
        source_id: doc-123
        text_retained: true
        embedding_retained: true
    retrieval_cache:
      invalidated: false
```

**Expected result:** High severity finding.

**Reason:** Deleted source content can still be retrieved through chunk text, embeddings, or cache entries.

## Case 3: Consent Withdrawal Does Not Affect Training Snapshots

```yaml
consent:
  user_id: user-77
  ai_training_opt_out: true
  changed_at: "2026-06-06"
training_data:
  snapshots:
    - id: ft-2026-05-01
      contains_user_id: user-77
      excluded_after_withdrawal: false
model_artifacts:
  retraining_decision: none
  unlearning_decision: none
```

**Expected result:** High severity finding.

**Reason:** Consent withdrawal is not propagated to existing fine-tuning data or model artifact risk decisions.

## Case 4: Complete Propagation Ledger

```yaml
deletion_ledger:
  request_id: dsar-456
  subject_id: user-77
  source_records:
    deleted: true
  embeddings:
    vector_ids:
      - vec-1
      - vec-2
    tombstoned: true
    retrieval_cache_invalidated: true
    reindexed_at: "2026-06-06T10:00:00Z"
  prompt_logs:
    redacted: true
    retention_exception: none
  training_snapshots:
    affected:
      - ft-2026-05-01
    action: exclude_from_next_training
    model_risk_decision: retrain_not_required_low_memorization_risk
  analytics_exports:
    purged: true
  provider_retention:
    llm_api: zero_data_retention_enabled
    embedding_api: deletion_confirmed
  backups:
    restore_guardrail: reapply_deletion_ledger
    legal_hold: none
```

**Expected result:** Pass for deletion propagation evidence if implementation evidence matches the ledger.

**Reason:** The workflow maps primary records to derived stores, deletes or redacts each downstream copy, handles provider retention, and prevents backup restore from resurrecting deleted data.

## Review Assertions

- Do not credit a DSAR endpoint unless derived AI stores are mapped.
- Confirm vector chunks, embeddings, metadata filters, replicas, and caches are deleted or tombstoned.
- Confirm consent withdrawal affects existing training snapshots and model artifact decisions.
- Confirm backup restore procedures reapply the deletion ledger.
