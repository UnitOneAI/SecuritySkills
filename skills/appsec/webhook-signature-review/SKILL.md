---
name: webhook-signature-review
description: >
  Reviews inbound webhook handlers for signature verification, raw-body
  canonicalization, timestamp freshness, replay protection, secret rotation,
  and source-trust mistakes. Auto-invoked when reviewing webhook receiver code,
  provider callback routes, HMAC verification middleware, or event-ingestion
  endpoints. Produces findings mapped to CWE-345, CWE-347, and OWASP ASVS.
tags: [appsec, webhook, hmac, authentication, replay]
role: [appsec-engineer, security-engineer]
phase: [build, review]
frameworks: [OWASP-ASVS, CWE]
difficulty: intermediate
time_estimate: "20-40min"
version: "1.0.0"
author: xiefuzheng713-alt
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[webhook-handler-file-or-directory]"
---

# Webhook Signature Review

## Purpose

If a target is provided via arguments, focus the review on: $ARGUMENTS

Review inbound webhook receivers that process events from payment processors,
identity providers, CI systems, chat platforms, Git hosts, and other external
systems. The review verifies that the receiver authenticates the event exactly
as the provider signed it, rejects stale or replayed deliveries, supports safe
secret rotation, and does not replace cryptographic verification with weak
source assumptions such as IP allowlists alone.

## Trigger Conditions

Use this skill when any of the following are present:

- Route names or files contain `webhook`, `callback`, `event`, `receiver`,
  `ingest`, `notification`, or provider-specific webhook names.
- Code reads signature-like headers such as `x-signature`, `stripe-signature`,
  `x-hub-signature-256`, `x-github-event`, `svix-signature`, or similar.
- Code computes HMAC, SHA-256 digests, or provider-specific signing strings for
  inbound HTTP requests.
- A handler processes provider events that can mutate accounts, billing state,
  deployments, permissions, messages, or user data.

## Scope Inventory

Before scoring findings, build an inventory of every inbound webhook endpoint.

1. **Provider and event type** -- Name the provider and list event names that
   the endpoint accepts.
2. **Business action** -- Record what each event can change: payment status,
   account access, deployment state, message delivery, audit records, or other
   side effects.
3. **Signature source** -- Identify the exact headers, payload bytes, timestamp
   fields, and provider documentation used for verification.
4. **Parser boundary** -- Confirm whether verification uses raw request bytes
   before JSON, form, XML, compression, or charset transformations.
5. **Idempotency and replay store** -- Identify the event id, nonce, delivery id,
   or digest key used to reject duplicate deliveries.
6. **Secret lifecycle** -- Determine where secrets live, how rotation works, and
   whether old and new secrets can overlap safely.
7. **Network assumptions** -- Document IP allowlists, mTLS, gateway validation,
   or private connectivity, but do not treat them as a replacement for message
   authentication unless the provider explicitly signs at that layer.

> Gate: Do not mark a webhook as verified until the signed input, timestamp
> window, replay key, and secret source are all identified.

## Detection Checklist

### 1. Raw Body Canonicalization

Flag handlers that verify a transformed body instead of the exact signed bytes.

High-confidence patterns:

- JSON parser runs before signature verification and the verifier signs
  `JSON.stringify(req.body)`, `json.dumps(request.json)`, or equivalent.
- Middleware globally consumes the request body before the webhook route can
  access raw bytes.
- Verification normalizes whitespace, key order, URL encoding, or charset
  without provider documentation requiring that normalization.
- The handler signs only selected fields instead of the provider's required
  signing string.

Required safe evidence:

- The route captures raw bytes before parsing.
- The signing string matches provider documentation, including timestamp,
  delimiter, payload bytes, and version prefix where applicable.
- Tests prove that reordered JSON or whitespace changes do not bypass the
  verifier unless the provider explicitly canonicalizes JSON.

### 2. Signature Algorithm and Constant-Time Compare

Flag weak or incomplete verification.

High-confidence patterns:

- Plain shared-secret equality such as `header == secret`.
- Unsigned or unauthenticated event ids accepted as proof of origin.
- MD5, SHA-1, or custom checksum used when the provider supports HMAC-SHA256 or
  stronger signing.
- Direct string comparison instead of constant-time comparison.
- Missing algorithm or version parsing, allowing downgrade to weaker signatures.

Required safe evidence:

- The verifier uses HMAC or the provider's asymmetric signature scheme.
- The comparison uses `hmac.compare_digest`, `crypto.timingSafeEqual`, or a
  provider SDK with documented constant-time verification.
- The expected digest length and algorithm version are checked before comparison.

### 3. Timestamp Freshness and Replay Protection

Flag handlers that accept valid old signatures indefinitely.

High-confidence patterns:

- No timestamp is included in the signed input.
- Timestamp exists but the handler never checks skew or age.
- The same event id, delivery id, nonce, or digest can be processed repeatedly.
- Replay keys are stored after side effects rather than before the business
  action is committed.

Required safe evidence:

- The timestamp is part of the signed input.
- The acceptable clock-skew window is documented and enforced, typically five to
  ten minutes unless the provider specifies otherwise.
- A durable replay store rejects duplicate event ids or signed digests before
  side effects occur.
- Idempotent handlers still record duplicate deliveries and prove that repeated
  events do not repeat money movement, privilege changes, or irreversible
  operations.

### 4. Secret Rotation and Multi-Tenant Binding

Flag handlers that cannot rotate webhook secrets safely or mix tenant secrets.

High-confidence patterns:

- One global webhook secret validates events for multiple tenants or providers.
- Rotation requires downtime or accepts both secrets forever.
- Tenant id is read from the unsigned body before selecting the verification
  secret.
- Test and production secrets share the same route without an environment or
  provider-account binding.

Required safe evidence:

- Secret lookup is bound to a trusted route, host, provider account id, or other
  signed metadata.
- Rotation supports a bounded overlap window and records which secret version
  verified the event.
- Secrets are stored in a secret manager or environment configuration, never in
  source code or logs.

### 5. Source Trust and Gateway Assumptions

Flag handlers that rely on source IP, user agent, or provider name without
message authentication.

High-confidence patterns:

- IP allowlist is the only authentication control.
- The handler trusts forwarded headers without confirming the trusted proxy
  chain.
- Gateway or load balancer verification is claimed but no policy, log, or
  direct-origin block evidence is present.
- mTLS is enabled at the edge but the app also exposes a bypass route.

Required safe evidence:

- Message-level signature verification occurs in the app or an enforced gateway.
- Direct-origin access is blocked when verification is delegated to a gateway.
- IP allowlists, mTLS, and private links are documented as defense-in-depth, not
  as the sole proof of authenticity.

## Findings Classification

Each finding produced by this review must include:

| Field | Description |
|---|---|
| ID | Sequential finding id, for example `WH-SIG-001` |
| Provider | Webhook provider or `custom` |
| Endpoint | Route, function, or file path |
| Event impact | Business action triggered by the event |
| Weakness | Raw-body mismatch, weak signature, stale timestamp, replay, rotation, or source-trust issue |
| Severity | Critical, High, Medium, Low, or Informational |
| CWE | CWE-345, CWE-347, CWE-294, CWE-613, or other applicable CWE |
| Evidence | Code snippet, configuration, test, or provider-doc mismatch |
| Exploit sketch | Minimal replay or forgery scenario without real secrets |
| Remediation | Concrete code/configuration change |
| Verification | Test or manual check that proves the fix |

### Severity Guidance

| Severity | Criteria |
|---|---|
| Critical | Forged or replayed webhook can trigger payment, account takeover, production deployment, privilege grant, or destructive business action without authentication. |
| High | Forged or replayed webhook can alter customer state, create records, leak sensitive data, or bypass approval flows. |
| Medium | Verification is present but incomplete, such as no replay store, weak rotation, or uncertain gateway evidence for moderate-impact events. |
| Low | Defense-in-depth weakness with limited impact, such as missing duplicate-delivery telemetry on already idempotent low-risk events. |
| Informational | Documentation, observability, or test coverage improvement with no current exploit path. |

## Output Format

Return a structured report:

```markdown
## Webhook Signature Review Report

**Scope:** [files/routes reviewed]
**Providers:** [provider names]
**Date:** [date]
**Reviewer:** AI Agent -- webhook-signature-review v1.0.0

### Summary

| Endpoint | Provider | Signed raw body | Timestamp checked | Replay protected | Result |
|---|---|---:|---:|---:|---|
| [route] | [provider] | Yes/No | Yes/No | Yes/No | Pass/Fail/Partial |

### Findings

#### WH-SIG-001: [title]
- **Severity:** [Critical|High|Medium|Low|Informational]
- **CWE:** [CWE id]
- **Endpoint:** [route/file]
- **Provider:** [provider]
- **Evidence:** [snippet or explanation]
- **Impact:** [business effect]
- **Remediation:** [specific fix]
- **Verification:** [test or check]
```

## Remediation Patterns

### Node/Express

- Capture raw bytes for the webhook route before any JSON parser mutates the
  request body.
- Build the signing string from the provider timestamp and raw bytes.
- Use `crypto.createHmac("sha256", secret)` or the provider SDK.
- Compare fixed-length buffers with `crypto.timingSafeEqual`.
- Reject timestamps outside the configured tolerance.
- Insert the event id or digest into a replay store before running side effects.

### Python/Flask

- Use `request.get_data(cache=False)` for raw bytes before reading
  `request.json`.
- Build the provider's exact signing string from timestamp and raw bytes.
- Use `hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()`.
- Compare with `hmac.compare_digest`.
- Reject stale timestamps and duplicate event ids before mutating state.

## Verification Tests

Run or adapt the examples under this skill directory:

- `tests/vulnerable/express-json-body.js` should be flagged for signing a
  reserialized JSON body and lacking replay protection.
- `tests/vulnerable/flask-no-replay.py` should be flagged for accepting old
  signatures and processing duplicate events.
- `tests/vulnerable/express-shared-secret.js` should be flagged for replacing
  message authentication with a shared secret header comparison.
- `tests/benign/express-raw-body-timestamp.js` should pass because it verifies
  raw bytes, timestamp freshness, constant-time comparison, and replay keys.
- `tests/benign/flask-raw-body-replay.py` should pass for equivalent Flask
  controls.
- `tests/benign/secret-rotation.js` should pass because route-bound secret
  versions are checked with a bounded overlap window.

## False Positive Controls

Do not flag the following as vulnerable without additional evidence:

- Provider SDK verification that is documented to use raw body bytes, timestamp
  tolerance, and constant-time comparison.
- Gateway-verified webhooks when direct-origin access is blocked and gateway
  logs/policy prove message-level signature verification.
- Public, no-side-effect subscription validation endpoints when they only echo a
  provider challenge and cannot mutate state.
- Duplicate delivery of idempotent events when the handler records and rejects
  repeated side effects.
- Test fixtures with fake secrets when they are clearly marked and not used in
  production configuration.

## References

- CWE-345: Insufficient Verification of Data Authenticity
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-294: Authentication Bypass by Capture-replay
- OWASP ASVS 4.0.3 V2.8 and V10.3
- Stripe webhook signature verification documentation
- GitHub webhook signature validation documentation
- Svix webhook verification documentation

## Changelog

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0.0 | 2026-06-10 | xiefuzheng713-alt | Initial webhook signature review skill |
