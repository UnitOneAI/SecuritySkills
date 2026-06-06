# Persistent Memory Integrity Evidence Fixtures

These fixtures calibrate the supplemental `AG04-MEM-*` evidence gates in `agentic-top-10`. They are intentionally small so reviewers can distinguish production-grade memory integrity controls from benign-looking vector-store configurations.

```yaml
case: approved_tool_memory_with_trust_tier_retrieval
memory_store:
  type: pgvector
  persistence: cross_session
write_path:
  allowed_sources:
    - trusted_tool_output
  approval_required_for_untrusted_sources: true
  deny_by_default: true
provenance:
  chain:
    - agent: research_agent
    - tool: "https://api.example.com/advisories"
    - raw_response: s3://audit-bucket/raw/adv-123.json
    - sanitizer: pii_and_prompt_injection_filter
    - memory_entry: mem_123
  actor_identity: svc-agent-research
  tenant_id: tenant_a
  trust_tier: verified_tool
  approval_state: approved
  ttl_days: 30
integrity:
  append_only_log: true
  record_digest: sha256:1234abcd
retrieval:
  filters_before_similarity:
    - tenant_id
    - agent_id
    - purpose
    - "trust_tier >= context.required_tier"
  rerank_signals:
    - similarity
    - recency
    - trust_score
quarantine:
  immediate_exclusion: true
  tombstone_preserves_audit: true
  invalidates:
    - session_context
    - embedding_cache
    - prompt_cache
    - replica_index
expected_decision: Pass
expected_findings: []
```

```yaml
case: untrusted_web_output_auto_saved_to_long_term_memory
memory_store:
  type: pgvector
  persistence: cross_session
write_path:
  allowed_sources:
    - user_uploaded_document
    - web_search_result
  approval_required_for_untrusted_sources: false
  deny_by_default: false
provenance:
  chain: missing
  actor_identity: agent
  source_uri: missing
  trust_tier: missing
  approval_state: missing
  ttl_days: missing
retrieval:
  filters_before_similarity:
    - tenant_id
  top_k: 8
expected_decision: Fail
expected_findings:
  - category: AG04
    check: AG04-MEM-01
    severity: High
    reason: Untrusted documents and web results can be promoted into cross-session memory without approval or deny-by-default enforcement.
  - category: AG04
    check: AG04-MEM-02
    severity: High
    reason: Saved memory lacks source URI, full provenance chain, trust tier, approval state, and TTL evidence.
  - category: AG04
    check: AG04-MEM-05
    severity: Medium
    reason: User and tool memories persist without TTL, review cadence, owner disposition, or trust promotion rules.
```

```yaml
case: similarity_only_retrieval_mixes_trust_boundaries
memory_store:
  type: chroma
  persistence: cross_session
contents:
  - system_seed_memory
  - developer_policy_note
  - user_personal_memory
  - agent_generated_note
  - external_tool_summary
provenance:
  trust_tiers_present: true
  approval_state_present: true
retrieval:
  filters_before_similarity: []
  ranking: vector_similarity_only
  tenant_filter: present
  required_tier_filter: missing
  agent_scope_filter: missing
expected_decision: Fail
expected_findings:
  - category: AG04
    check: AG04-MEM-03
    severity: High
    reason: Low-trust memories can displace system or developer context because retrieval applies no trust-tier or agent-scope filter before similarity ranking.
```

```yaml
case: vector_delete_leaves_derived_memory_artifacts
memory_store:
  type: pinecone
  persistence: cross_session
remediation:
  delete_endpoint: "/memory/{id}"
  tombstone: missing
  audit_replay: missing
  immediate_retrieval_exclusion: missing
derived_artifacts:
  summary_cache: not_invalidated
  embedding_cache: not_invalidated
  prompt_cache: unknown
  session_context: not_invalidated
  replica_index: not_reviewed
expected_decision: Fail
expected_findings:
  - category: AG04
    check: AG04-MEM-06
    severity: High
    reason: Poisoned memory removal depends on destructive row deletion with no tombstone, immediate retrieval exclusion, or replay audit.
  - category: AG04
    check: AG04-MEM-07
    severity: High
    reason: Derived summaries, embeddings, prompt caches, session context, and replicas remain usable after the primary vector row is deleted.
```

```yaml
case: ephemeral_session_memory_with_injection_handling
memory_store:
  type: in_process_session
  persistence: current_task_only
write_path:
  allowed_sources:
    - current_user_message
    - tool_output
  cross_session_promotion: disabled
provenance:
  source_event_id: present
  trust_tier: session_untrusted
  approval_state: not_promoted
  ttl: session_end
retrieval:
  filters_before_reuse:
    - session_id
    - task_id
  prompt_injection_filter_before_reuse: true
quarantine:
  clear_session_memory_on_detection: true
expected_decision: Pass
expected_findings: []
```

```yaml
case: user_personal_memory_isolated_from_system_trust
memory_store:
  type: conversation_db
  persistence: cross_session
write_path:
  allowed_sources:
    - authenticated_user_preference
  system_or_developer_promotion: requires_manual_approval
provenance:
  actor_identity: user_123
  tenant_id: tenant_a
  trust_tier: user_personal
  approval_state: user_authored
  ttl_days: 365
retrieval:
  filters_before_similarity:
    - user_id
    - tenant_id
    - "trust_tier <= user_personal"
  excluded_from_system_prompts: true
removal:
  user_delete: true
  tombstone_preserves_audit: true
  caches_invalidated: true
expected_decision: Pass
expected_findings: []
```

```yaml
case: memory_store_visible_but_security_artifacts_missing
memory_store:
  type: redis_vector
  persistence: cross_session
available_evidence:
  - redis_index_configuration
  - memory_write_function_name
missing_artifacts:
  - allowed_writer_policy
  - source_provenance_schema
  - trust_tier_schema
  - approval_workflow
  - retrieval_filter_code
  - integrity_or_audit_log
  - quarantine_runbook
  - cache_invalidation_plan
expected_decision: Not Evaluable
expected_findings:
  - category: AG04
    check: AG04-MEM-01
    severity: Medium
    reason: The memory store and write path are visible, but authorization, provenance, retrieval, integrity, and remediation evidence is missing from the review package.
  - category: AG04
    check: AG04-MEM-04
    severity: Medium
    reason: No tamper-evident log, digest, immutable event stream, or equivalent integrity artifact was provided for memory writes and updates.
```
