# Retrieval Authorization Edge Cases

These fixtures validate LLM08 review behavior for RAG retrieval authorization across vector search, cache, reranking, and prompt assembly.

## Case 1: Tenant Filter Without Post-Retrieval ACL Check

```yaml
retrieval:
  pre_query_filter:
    tenant_id: request.tenant_id
  post_retrieval_acl_check: false
  prompt_assembly:
    include_all_returned_chunks: true
```

**Expected result:** High severity finding.

**Reason:** The initial query is scoped, but stale metadata, shared documents, or misindexed chunks can still enter the prompt without validation against the user's current ACL.

## Case 2: Shared Retrieval Cache Keyed Only by Query

```yaml
cache:
  enabled: true
  key_fields:
    - normalized_query
    - embedding_model
  missing_key_fields:
    - tenant_id
    - user_id
    - permission_version
    - collection_id
```

**Expected result:** High severity finding.

**Reason:** One user's authorized retrieval result can be reused for another user or tenant with the same query.

## Case 3: Reranker Drops Authorization Metadata

```yaml
pipeline:
  vector_results:
    metadata:
      - document_id
      - tenant_id
      - acl_version
  reranker:
    input_fields:
      - text
      - score
    output_fields:
      - text
      - rerank_score
  final_context:
    uses_reranker_output_only: true
```

**Expected result:** High severity finding.

**Reason:** The reranker output cannot be rechecked against source document ACLs before prompt assembly.

## Case 4: Complete Retrieval Authorization Chain

```yaml
rag_authorization:
  pre_query_filter:
    tenant_id: request.tenant_id
    user_id: request.user_id
    groups: request.groups
    permission_version: request.permission_version
  vector_query:
    collection: tenant_scoped
    include_metadata:
      - document_id
      - chunk_id
      - tenant_id
      - acl_hash
      - classification
      - permission_version
  cache:
    key_fields:
      - tenant_id
      - user_id
      - groups_hash
      - permission_version
      - query_hash
      - embedding_model
      - collection_id
  reranker:
    preserves_metadata: true
  post_retrieval_acl_check:
    before_rerank: true
    after_rerank: true
    before_prompt_assembly: true
  invalidation_events:
    - group_membership_changed
    - document_acl_changed
    - document_deleted
    - classification_changed
```

**Expected result:** Pass for retrieval authorization if implementation evidence confirms each enforcement point.

**Reason:** Authorization is enforced before query construction, after retrieval, after reranking, and before prompt assembly, with cache keys and invalidation tied to permission state.

## Review Assertions

- Do not credit tenant filters without post-retrieval ACL validation.
- Confirm retrieval cache keys include permission scope and permission version.
- Confirm rerankers and hybrid search preserve source ACL metadata.
- Confirm permission changes invalidate indexes, caches, and assembled prompt contexts.
