# AI Data Privacy — Data Retention Risk Table

## AI-Specific Retention Considerations

| Data Type | Retention Risk | Recommended Approach |
|---|---|---|
| Conversation logs (prompt/completion) | Contain user PII, business data, potentially sensitive queries | Define retention period aligned with legal basis; auto-purge; redact PII in long-term analytics |
| Vector store embeddings | Embeddings can be partially inverted to recover source text; accumulate indefinitely | TTL per document; delete embeddings when source document access is revoked |
| Fine-tuning datasets | May contain PII; needed for reproducibility but not for ongoing inference | Archive with access controls after training; delete when no longer needed for retraining |
| Model checkpoints | Encode training data in weights; large storage footprint | Retain only production and rollback versions; delete intermediate checkpoints |
| RAG source documents | Original documents with full content including PII | Align retention with document source system; propagate deletions to vector store |
| Evaluation/test datasets | May contain real user data used for testing | Anonymize or use synthetic data; apply same retention as production data |

## Retention Risk Matrix

| Risk Factor | High Risk | Medium Risk | Low Risk |
|---|---|---|---|
| Data contains PII | No retention policy | Retention > 90 days | Retention <= 30 days with auto-purge |
| Data contains PHI | Any retention without HIPAA controls | Retention with partial controls | HIPAA-compliant retention with BAA |
| Backup propagation | Backups retain beyond primary TTL | Backup TTL aligned but manual | Automated backup lifecycle aligned |
| Cross-system deletion | Deletion does not propagate to AI stores | Partial propagation | Full cascade deletion verified |
| Encryption at rest | Unencrypted storage | Encrypted but shared keys | Encrypted with per-tenant keys |
