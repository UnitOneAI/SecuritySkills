# RAG Data Poisoning Review Patterns

## Vulnerable Patterns

| Pattern | Why it matters | Review signal |
|---|---|---|
| Shared vector namespace for all tenants | Cross-tenant chunks can appear in answers | `namespace: "default"`, no tenant field in query |
| Client-controlled retrieval filter | User or model can weaken scope | request body contains `filter`, `where`, or `namespace` passed through |
| Metadata dropped before embedding | Source trust and ACL cannot be enforced later | chunk contains `text` only after parser step |
| Unreviewed public ingestion | Low-trust content becomes authoritative context | crawler or upload path writes directly to production index |
| Stale chunk lifecycle | Revoked or deleted content remains retrievable | no delete-by-source, no ACL-change invalidation |
| Prompt-region mixing | Retrieved data is formatted like application policy | context template lacks source labels or quote boundaries |
| Action from retrieval alone | Corpus text can drive side effects | model response creates tickets, emails, exports, or admin changes |
| Cache missing auth key | One user's retrieval result is reused for another | cache key omits tenant, role, ACL version, or document scope |

## Safe Patterns

| Control | Expected evidence |
|---|---|
| Server-side tenant and ACL filters | filters built from authenticated identity, not client text |
| Durable provenance metadata | source ID, version, owner, trust tier, tenant, ACL, parser, and content hash |
| Trust-tiered indexes | untrusted, reviewed, and authoritative sources separated |
| Explicit context boundaries | retrieved chunks quoted with source labels and never treated as policy |
| Lifecycle propagation | source deletion and ACL revocation remove chunks and caches |
| Retrieval audit trail | logs include requester, filter, source, chunk ID, score, model, and answer ID |
| Deterministic action gates | LLM-suggested actions pass non-LLM authorization and policy checks |

## Suggested Search Terms

- `vector.upsert`, `index.add`, `collection.add`, `embed_documents`
- `metadata`, `tenant`, `workspace`, `acl`, `source`, `namespace`
- `where`, `filter`, `pre_filter`, `post_filter`, `rerank`
- `delete_by_source`, `reindex`, `sync`, `crawler`, `document_loader`
- `retrieved_context`, `sources`, `citations`, `context_chunks`

## Review Questions

1. Can a low-trust actor write content that high-trust users later retrieve?
2. Does every retrieved chunk carry tenant, ACL, source, and version metadata?
3. Are authorization filters applied before retrieval and re-ranking?
4. Can stale chunks survive source deletion, tenant migration, or ACL revocation?
5. Does prompt assembly make it clear that retrieved text is data?
6. Are privileged actions gated by deterministic authorization checks?
