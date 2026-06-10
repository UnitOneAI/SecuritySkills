# RAG Data Poisoning Review

This skill reviews retrieval-augmented generation systems for poisoning risks in
document ingestion, vector metadata, retrieval filtering, context assembly, and
index lifecycle controls.

It is narrower than a general prompt-injection review. The focus is whether
untrusted or stale corpus content can become trusted model context, cross tenant
boundaries, or influence privileged workflows without durable provenance and
authorization checks.

## Included Fixtures

Vulnerable examples:

- `fixtures/vulnerable/python_untrusted_ingest.py`
- `fixtures/vulnerable/typescript_tenantless_retrieval.js`
- `fixtures/vulnerable/python_vector_metadata_loss.py`

Benign examples:

- `fixtures/benign/python_provenance_gate.py`
- `fixtures/benign/typescript_tenant_scoped_retrieval.js`
- `fixtures/benign/python_signed_corpus_manifest.py`

## Review Targets

- document upload and connector sync paths;
- vector DB namespace and metadata schema;
- tenant, role, and document ACL filters;
- prompt context assembly boundaries;
- deletion, revocation, re-index, and cache invalidation workflows;
- audit events for retrieved chunks and answer citations.

## Validation

Run syntax checks for the included fixtures:

```bash
python -m py_compile fixtures/vulnerable/python_untrusted_ingest.py \
  fixtures/vulnerable/python_vector_metadata_loss.py \
  fixtures/benign/python_provenance_gate.py \
  fixtures/benign/python_signed_corpus_manifest.py

node --check fixtures/vulnerable/typescript_tenantless_retrieval.js
node --check fixtures/benign/typescript_tenant_scoped_retrieval.js
```

Use the checklist in `SKILL.md` to produce findings and verification evidence.
