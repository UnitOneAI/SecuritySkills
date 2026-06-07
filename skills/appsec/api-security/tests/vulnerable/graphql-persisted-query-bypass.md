# Vulnerable: persisted-query policy accepts raw documents

## Scenario

Production policy says public clients must use persisted query hashes, but raw query documents are still accepted when a hash is unknown.

```yaml
prod_policy:
  persisted_queries_required: true
  introspection: disabled
observed_behavior:
  unknown_sha256_hash: fallback_to_raw_query
  raw_query_document: accepted
  rejection_status_for_unknown_hash: none
  complexity_rejection_log: missing
```

## Expected Findings

- `GQL-OPS-05` because persisted-query/safelist policy can be bypassed with raw query documents.
- `GQL-OPS-03` if no depth/complexity rejection evidence is available for raw documents.
