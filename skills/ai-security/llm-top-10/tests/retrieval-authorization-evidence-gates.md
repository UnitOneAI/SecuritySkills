# LLM08 Retrieval Authorization Evidence Gates

These fixtures calibrate the `llm-top-10` LLM08 retrieval authorization gate. A review should prove that authorization is enforced before query construction, after retrieval, after reranking or aggregation, before prompt assembly, and across cache/index invalidation events.

## Vulnerable: Tenant Filter Without Post-Retrieval ACL Check

```yaml
case: tenant-filter-no-post-retrieval-acl
retrieval:
  pre_query_filter:
    tenant_id: request.tenant_id
  vector_store_collection: shared_by_tenant
  post_retrieval_acl_check:
    after_vector_search: false
    after_rerank: false
    before_prompt_assembly: false
prompt_assembly:
  include_all_returned_chunks: true
expected_result:
  finding_codes:
    - LLM08-RA-02
    - LLM08-RA-08
  decision: Fail
  severity: High
  reason: A tenant filter alone does not prove each returned chunk is authorized for the current user and permission version.
```

## Vulnerable: Shared Cache Keyed Only By Query

```yaml
case: shared-cache-query-only
cache:
  enabled: true
  key_fields:
    - normalized_query
    - embedding_model
  omitted_key_fields:
    - tenant_id
    - user_id
    - groups_hash
    - permission_version
    - collection_id
    - source_acl_hash
expected_result:
  finding_codes:
    - LLM08-RA-03
  decision: Fail
  severity: High
  reason: One user's authorized retrieval result can be reused for another user or tenant with the same query.
```

## Vulnerable: Reranker Drops Authorization Metadata

```yaml
case: reranker-drops-acl-metadata
pipeline:
  vector_results:
    metadata:
      - document_id
      - chunk_id
      - tenant_id
      - acl_hash
      - permission_version
  reranker:
    input_fields:
      - text
      - score
    output_fields:
      - text
      - rerank_score
  final_context:
    uses_reranker_output_only: true
expected_result:
  finding_codes:
    - LLM08-RA-04
  decision: Fail
  severity: High
  reason: The final context cannot be rechecked against source document or chunk ACLs before prompt assembly.
```

## Vulnerable: Hybrid Search Merges Unauthorized Keyword Results

```yaml
case: hybrid-search-keyword-results-unscoped
retrieval:
  vector_query_filter:
    tenant_id: tenant-a
    permission_version: pv-42
  bm25_query_filter:
    tenant_id: missing
    acl_filter: missing
  merge_strategy: reciprocal_rank_fusion
  post_merge_acl_check: false
expected_result:
  finding_codes:
    - LLM08-RA-01
    - LLM08-RA-04
  decision: Fail
  severity: High
  reason: Hybrid search can reintroduce unauthorized keyword results after the vector path was filtered.
```

## Vulnerable: Shared Collection Assumed Public

```yaml
case: shared-collection-assumed-public
collection:
  name: shared-reference-docs
  contains:
    - public_docs
    - tenant_private_docs
public_exception_evidence:
  classification: missing
  immutable_source_metadata: missing
  owner_approval: missing
  mixed_content_check: missing
expected_result:
  finding_codes:
    - LLM08-RA-05
  decision: Partial
  severity: High
  reason: Shared collection membership is not proof that each retrieved chunk is public.
```

## Vulnerable: Permission Change Does Not Invalidate Cache

```yaml
case: group-membership-change-cache-not-invalidated
identity:
  user_id: user-123
  previous_groups_hash: g-old
  current_groups_hash: g-new
  permission_version: pv-43
cache:
  stored_permission_version: pv-42
  invalidation_events:
    group_membership_changed: ignored
    document_acl_changed: handled
    document_deleted: handled
prompt_context_store:
  previous_context_reused: true
expected_result:
  finding_codes:
    - LLM08-RA-06
  decision: Fail
  severity: High
  reason: Previously authorized chunks can remain available after group membership changes.
```

## Vulnerable: Chunk-Level Redaction Boundary Missing

```yaml
case: document-acl-ignores-redacted-chunk
document:
  id: doc-789
  document_acl: accessible_to_user
  chunks:
    - id: chunk-public
      classification: internal
      allowed: true
    - id: chunk-redacted
      classification: restricted
      allowed: false
retrieval:
  checks_document_acl_only: true
  checks_chunk_acl: false
expected_result:
  finding_codes:
    - LLM08-RA-07
  decision: Fail
  severity: High
  reason: Document-level access does not authorize restricted chunks or redacted sections.
```

## Benign: End-to-End Retrieval Authorization Chain

```yaml
case: complete-retrieval-authorization-chain
identity:
  tenant_id: tenant-a
  user_id: user-123
  groups_hash: groups-a1
  permission_version: pv-44
retrieval:
  pre_query_filter:
    tenant_id: tenant-a
    user_id: user-123
    groups_hash: groups-a1
    permission_version: pv-44
    classification_max: confidential
  vector_results_metadata:
    - document_id
    - chunk_id
    - tenant_id
    - acl_hash
    - classification
    - permission_version
  cache_key_fields:
    - tenant_id
    - user_id
    - groups_hash
    - permission_version
    - query_hash
    - embedding_model
    - collection_id
    - source_acl_hash
  post_retrieval_acl_check:
    after_vector_search: true
    after_rerank: true
    before_prompt_assembly: true
  reranker_preserves_metadata: true
  invalidation_events:
    - group_membership_changed
    - document_acl_changed
    - document_deleted
    - classification_changed
    - embedding_model_changed
expected_result:
  finding_codes: []
  decision: Pass
  severity: Informational
  reason: Authorization is enforced across query construction, cache scope, reranking, prompt assembly, and permission invalidation.
```
