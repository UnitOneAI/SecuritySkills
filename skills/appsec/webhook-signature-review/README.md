# Webhook Signature Review

This skill reviews inbound webhook receivers for signature verification,
raw-body canonicalization, timestamp freshness, replay protection, secret
rotation, and weak source-trust assumptions.

## Three-step usage

1. Point the agent at webhook receiver code, for example an Express, Flask, or
   provider callback route.
2. Run the `webhook-signature-review` skill and capture the inventory table plus
   findings.
3. Verify fixes with the included vulnerable and benign examples before marking
   the review complete.

## Included evidence

- Three vulnerable fixtures under `tests/vulnerable/`.
- Three benign fixtures under `tests/benign/`.
- A pattern reference under `references/patterns.md`.

The examples are intentionally dependency-light so reviewers can inspect the
security properties without running provider-specific SDKs or using real
webhook secrets.
