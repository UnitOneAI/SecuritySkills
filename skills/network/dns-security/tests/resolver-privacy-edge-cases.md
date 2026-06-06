# Resolver Privacy Edge Cases

These fixtures verify that DNSSEC, encrypted transport, RPZ, and query logging do not hide resolver privacy gaps.

## Case 1: Secure Resolver With QNAME Minimization Disabled

```yaml
resolver: corp-recursive-1
dnssec_validation: enabled
upstream_transport: DoT
rpz_filtering: enabled
qname_minimization: disabled
compatibility_exception: null
```

Expected review:

- DNSSEC and encrypted transport can pass.
- Resolver Privacy Posture records `QNAME Minimization` as `Disabled`.
- Finding is Medium unless compatibility evidence explains the exception.

## Case 2: EDNS Client Subnet Forwarded With Full Client Prefix

```yaml
resolver: protective-dns
ecs:
  mode: forwarded
  ipv4_prefix_length: 32
  ipv6_prefix_length: 128
  exception_owner: null
  cdn_performance_justification: null
```

Expected review:

- `ECS Forwarding` is `Full`.
- Finding is Medium because client-specific prefixes are forwarded without a documented exception.
- Remediation recommends disabling ECS or coarsening prefixes with owner/review evidence.

## Case 3: Detailed Query Logs Retained for One Year

```yaml
resolver: dns-analytics
query_logs:
  fields:
    - client_ip
    - authenticated_user
    - full_qname
    - response_code
    - ecs_prefix
  retention_days: 365
  encrypted_at_rest: false
  access_review: missing
```

Expected review:

- `Log Detail` is `Full`.
- Finding is High because user-identifiable DNS logs are retained long-term without encryption, access review, or minimization evidence.
- Report records retention and access-control gaps separately from exfiltration detection readiness.

## Case 4: Bounded Security Logging With Privacy Evidence

```yaml
resolver: soc-dns
qname_minimization: enabled
ecs:
  mode: disabled
query_logs:
  fields:
    - client_subnet_coarse
    - qname_hash
    - response_code
  retention_days: 14
  encrypted_at_rest: true
  access_review: quarterly
  purpose: threat_hunting
```

Expected review:

- Resolver Privacy Posture is Pass.
- Security logging can remain enabled because retention, access controls, and minimization evidence are documented.
