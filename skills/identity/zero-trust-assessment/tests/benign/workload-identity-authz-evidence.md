# Benign: Workload Identity Is Bound To Service Authorization

This fixture should pass because non-human access is tied to a workload identity, a trust domain, short-lived credentials, and an explicit authorization policy.

```text
flow: checkout-api -> inventory-api
workload_identity_provider: SPIFFE/SPIRE
source_identity: spiffe://prod.example/ns/shop/sa/checkout-api
destination_resource: inventory-api /v1/reservations
credential_type: SVID certificate
credential_ttl: 30m
trust_domain: prod.example
authorization_policy: allow checkout-api to POST /v1/reservations only
default_deny: enabled for namespace
rotation_revocation: automated SVID rotation plus workload registration owner
audit_evidence: service-mesh access logs include source identity, destination, method, policy id, and decision
owner: platform-identity
```

Expected result: pass. The assessment can score workload access above Initial because identity, trust boundary, TTL, owner, default-deny authorization, and audit evidence are all present.
