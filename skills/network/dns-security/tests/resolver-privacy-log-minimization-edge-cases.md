# Resolver Privacy and Log Minimization Edge Cases

These fixtures calibrate the `dns-security` resolver privacy gate. A review should not pass a recursive resolver based only on DNSSEC, encrypted transport, protective DNS, or query logging when QNAME minimization, EDNS Client Subnet behavior, log fields, retention, access controls, or privacy policy evidence is missing.

## Vulnerable: Secure Resolver With QNAME Minimization Disabled

```yaml
case: secure-resolver-qname-minimization-disabled
resolver: corp-recursive-1
controls:
  dnssec_validation: enabled
  upstream_transport: dot
  rpz_filtering: enabled
  query_logging: enabled
privacy_evidence:
  qname_minimization: disabled
  resolver_supports_qname_minimization: true
  compatibility_exception: missing
  edns_client_subnet: disabled
  log_retention_days: 30
expected_result:
  finding_codes:
    - DNS-PRIV-01
  decision: Fail
  severity: Medium
  reason: DNSSEC, DoT, RPZ, and logging do not offset full-QNAME disclosure during iterative resolution.
```

## Vulnerable: Full EDNS Client Subnet Forwarding

```yaml
case: full-ecs-forwarding-without-exception
resolver: protective-dns-edge
edns_client_subnet:
  mode: forwarded
  ipv4_prefix_length: 32
  ipv6_prefix_length: 128
  destinations:
    - cdn-authoritative
    - upstream-recursive
exception:
  owner: missing
  affected_domains: missing
  review_date: missing
  performance_justification: missing
expected_result:
  finding_codes:
    - DNS-PRIV-02
    - DNS-PRIV-03
  decision: Fail
  severity: High
  reason: Full client prefixes are forwarded externally without owner, scope, prefix, and review evidence.
```

## Vulnerable: Long-Lived Detailed DNS Logs

```yaml
case: detailed-query-logs-one-year-retention
resolver: dns-analytics
query_logs:
  fields:
    - client_ip
    - authenticated_user
    - full_qname
    - response_code
    - response_data
    - ecs_prefix
  retention_days: 365
  aggregation: none
  pseudonymization: none
  encrypted_at_rest: false
  access_review: missing
  backup_deletion_path: missing
expected_result:
  finding_codes:
    - DNS-PRIV-04
    - DNS-PRIV-05
  decision: Fail
  severity: High
  reason: User-identifiable DNS history is retained long-term without minimization, encryption, access review, or deletion evidence.
```

## Vulnerable: Managed Resolver Policy Missing

```yaml
case: managed-resolver-policy-not-provided
resolver: external-protective-dns
provider_evidence:
  privacy_policy_url: missing
  retention_days: unknown
  sharing_terms: unknown
  operator_access_controls: unknown
  subprocessor_list: unknown
local_evidence:
  dnssec_validation: enabled
  doh_forwarding: enabled
  rpz_filtering: enabled
expected_result:
  finding_codes:
    - DNS-PRIV-06
    - DNS-PRIV-09
  decision: Not Evaluable
  severity: Low
  reason: Managed resolver privacy cannot be passed without provider retention, sharing, and operator-access evidence.
```

## Vulnerable: Threat-Hunting Exception Without Governance

```yaml
case: threat-hunting-logs-without-expiry
resolver: incident-response-dns
query_logs:
  fields:
    - client_ip
    - full_qname
    - authenticated_user
  retention_days: 180
  purpose: threat_hunting
exception:
  owner: soc
  incident_ticket: missing
  affected_users: all_employees
  expiration_date: missing
  access_review: annual
expected_result:
  finding_codes:
    - DNS-PRIV-07
  decision: Partial
  severity: Medium
  reason: Detailed logs may be justified during investigation, but the exception lacks ticket, expiry, scope reduction, and current access-review evidence.
```

## Vulnerable: Encrypted DNS Mistaken For Log Minimization

```yaml
case: doh-treated-as-log-minimization
resolver: browser-gateway
transport:
  client_to_resolver: doh
  resolver_to_upstream: doh
privacy_evidence:
  qname_minimization: unknown
  edns_client_subnet: unknown
  query_log_fields: unknown
  retention_days: unknown
review_conclusion: pass_because_dns_is_encrypted
expected_result:
  finding_codes:
    - DNS-PRIV-08
    - DNS-PRIV-09
  decision: Not Evaluable
  severity: Medium
  reason: Encrypted transport protects queries in transit but does not prove resolver-side minimization or retention controls.
```

## Benign: Bounded Protective DNS Logging

```yaml
case: bounded-protective-dns-logging
resolver: soc-protective-dns
privacy_evidence:
  qname_minimization: enabled
  edns_client_subnet:
    mode: coarse
    ipv4_prefix_length: 24
    ipv6_prefix_length: 56
    exception_owner: network-performance
    review_date: "2026-05-15"
  query_logs:
    fields:
      - client_subnet_coarse
      - qname_hash
      - response_code
      - threat_category
    retention_days: 14
    aggregation: daily
    encrypted_at_rest: true
    access_review: quarterly
    deletion_path: documented
  provider_policy:
    retention_statement: present
    sharing_terms: documented
    operator_access_controls: documented
expected_result:
  finding_codes: []
  decision: Pass
  severity: Informational
  reason: Resolver privacy, ECS scoping, log minimization, retention, access, and provider policy evidence are documented.
```
