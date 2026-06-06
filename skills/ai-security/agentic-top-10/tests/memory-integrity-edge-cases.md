# Memory Integrity Edge Cases

These fixtures validate AG04 review behavior for persistent agent memory systems.

## Case 1: Untrusted Document Summary Promoted to Long-Term Memory

```yaml
memory:
  store: pgvector
  write_sources:
    - user_uploaded_documents
    - agent_summaries
  promotion_policy: automatic
  metadata:
    source: optional
    trust_tier: none
```

**Expected result:** Fail for AG04.

**Reason:** User-controlled content can become cross-session memory without approval, source identity, trust tier, TTL, or immutable provenance.

## Case 2: Retrieval Mixes Trust Tiers by Similarity Only

```yaml
retrieval:
  index: shared_agent_memory
  top_k: 8
  rank_by: cosine_similarity
  filters: []
prompt_assembly:
  memory_position: before_system_policy_summary
```

**Expected result:** Fail or High severity Partial.

**Reason:** User-sourced and agent-generated memories can outrank trusted operational context. The prompt assembly order increases the chance that poisoned memory influences future instructions.

## Case 3: Delete Endpoint Leaves Derived Embeddings and Caches

```yaml
memory_delete:
  endpoint: DELETE /memory/{id}
  removes:
    - primary_record
  does_not_remove:
    - embedding_vector
    - summarized_profile
    - retrieval_cache
    - analytics_export
```

**Expected result:** Partial.

**Reason:** The primary record can be deleted, but derived data can still reintroduce poisoned content into future prompts or audits.

## Case 4: Quarantine With Audit Replay and Trust Labels

```yaml
memory:
  store: signed_append_log
  write_policy:
    user_context: requires_validation
    tool_output: requires_sanitization
    system_notes: operator_approved
  metadata:
    required:
      - source_type
      - source_identity
      - creating_agent
      - approval_state
      - trust_tier
      - ttl
      - content_hash
  retrieval:
    required_filters:
      - trust_tier
      - user_scope
      - agent_scope
  incident_response:
    quarantine: true
    tombstone: true
    reembed_after_removal: true
    invalidate_prompt_cache: true
    audit_replay: true
```

**Expected result:** Pass for the AG04 memory integrity lifecycle if implementation evidence exists.

**Reason:** The design covers controlled writes, provenance, trust-tiered retrieval, containment, derived data cleanup, and replayable audit history.

## Review Assertions

- Do not treat a managed vector database as proof of memory integrity.
- Require source attribution and trust labels before long-term reuse.
- Check retrieval filters and prompt assembly order, not only write controls.
- Confirm poisoning cleanup covers embeddings, summaries, caches, replicas, and exports.
