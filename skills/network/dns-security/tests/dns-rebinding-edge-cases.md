# DNS Rebinding Evidence Fixtures

These fixtures calibrate the supplemental `DNS-REBIND-*` evidence gates in `dns-security`.

```yaml
case: unbound_blocks_public_private_answers_with_scoped_internal_exception
resolver:
  type: unbound
  rebinding_policy:
    private_address:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.0/8
      - 169.254.0.0/16
      - ::1/128
      - fc00::/7
      - fe80::/10
    private_domain:
      - corp.example
exception:
  domain: corp.example
  owner: network-platform
  forwarding_authority: corp-internal-dns
  allowed_private_ranges:
    - 10.20.0.0/16
  expiry: "2026-12-31"
monitoring:
  low_ttl_public_to_private: enabled
expected_decision: Pass
expected_findings: []
```

```yaml
case: public_domain_resolves_to_loopback_rfc1918_and_metadata
resolver:
  type: recursive
  rebinding_policy:
    stop_dns_rebind: disabled
public_answer:
  name: attacker.example
  ttl: 1
  A:
    - 127.0.0.1
    - 192.168.1.1
    - 169.254.169.254
monitoring:
  low_ttl_public_to_private: missing
expected_decision: Fail
expected_findings:
  - check: DNS-REBIND-01
    severity: High
    reason: Public-domain answers to loopback, RFC1918, and metadata ranges are accepted without resolver-side protection.
  - check: DNS-REBIND-04
    severity: Medium
    reason: Low-TTL public-to-private answer transitions are not monitored.
```

```yaml
case: ipv6_rebinding_ranges_missing
resolver:
  type: dnsmasq
  rebinding_policy:
    stop_dns_rebind: true
    covered_ranges:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.0/8
public_answer:
  name: rebinder.example
  AAAA:
    - ::1
    - fe80::1
    - fd00::10
expected_decision: Fail
expected_findings:
  - check: DNS-REBIND-02
    severity: High
    reason: Rebinding protection covers IPv4 ranges but omits IPv6 loopback, link-local, and unique-local ranges.
```

```yaml
case: private_domain_exception_missing_owner_and_expiry
resolver:
  type: pihole
  rebinding_policy:
    stop_dns_rebind: true
exception:
  domain: nas.vendor.example
  allowed_private_ranges:
    - 192.168.1.0/24
  owner: missing
  business_reason: missing
  expiry: missing
expected_decision: Fail
expected_findings:
  - check: DNS-REBIND-03
    severity: Medium
    reason: Private-domain exception lacks owner, business reason, and expiry evidence.
```

```yaml
case: dnssec_signed_attacker_domain_returns_private_address
resolver:
  dnssec_validation: enabled
  rebinding_policy:
    private_address_filtering: missing
public_answer:
  name: signed-attacker.example
  dnssec_status: secure
  A:
    - 10.0.0.5
review_claim: DNSSEC validation makes the answer safe
expected_decision: Fail
expected_findings:
  - check: DNS-REBIND-06
    severity: High
    reason: DNSSEC validates answer integrity but does not authorize private-address answers from attacker-controlled public domains.
```

```yaml
case: ssrf_client_validates_hostname_only_before_dns_resolution
application_context:
  feature: link_preview
  allowlist: "*.example.net"
  dns_rebinding_prone: true
resolver:
  rebinding_policy:
    private_address_filtering: missing
client_behavior:
  validates_hostname_before_dns: true
  re_resolves_at_connect_time: false
  rechecks_resolved_ip_range: false
expected_decision: Fail
expected_findings:
  - check: DNS-REBIND-05
    severity: High
    reason: SSRF-prone client validates only the hostname and does not re-check resolved IP ranges at connect time.
```

```yaml
case: resolver_policy_visible_but_telemetry_missing
resolver:
  type: bind
  rebinding_policy:
    response_policy_zone: present
available_evidence:
  - named_conf
  - rpz_zone
missing_artifacts:
  - private_address_range_coverage
  - split_horizon_exception_register
  - resolver_query_logs
  - low_ttl_transition_rule
  - siem_forwarding
expected_decision: Not Evaluable
expected_findings:
  - check: DNS-REBIND-07
    severity: Medium
    reason: Resolver policy exists, but private-range coverage, exception governance, and monitoring evidence are missing.
```
