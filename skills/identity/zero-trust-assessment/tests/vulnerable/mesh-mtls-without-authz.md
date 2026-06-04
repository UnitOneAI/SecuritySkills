# Vulnerable: Service Mesh Has mTLS But No Authorization Policy Evidence

This fixture should fail because encrypted peer authentication alone does not prove least-privilege service authorization.

```text
flow: all workloads in prod namespace
workload_identity_provider: service mesh certificates
mtls_mode: STRICT
trust_domain: cluster.local
credential_ttl: 24h
authorization_policy: not found
default_deny: disabled
allowed_sources: all workloads in namespace
allowed_destinations: all services in namespace
audit_evidence: connection logs show certificate identity but no policy decision id
rotation_revocation: certificate rotation exists, workload decommissioning evidence missing
```

Expected result: fail. mTLS authenticates peers and encrypts traffic, but the assessment must still require source-to-destination authorization policy, default-deny posture, policy decision evidence, and lifecycle controls before scoring the workload pillar as Advanced.
