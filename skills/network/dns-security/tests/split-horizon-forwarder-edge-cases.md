# Split-Horizon and Conditional Forwarder Edge Cases

These fixtures verify that `dns-security` distinguishes intentional private DNS views from leaks, resolver bypasses, and incomplete evidence.

```yaml
case_id: DNS-SPLIT-01
title: BIND split-horizon view is scoped to internal clients
platform: BIND
view_scope:
  internal:
    match_clients:
      - 10.0.0.0/8
    recursion: true
    zone: corp.example.com
  external:
    match_clients:
      - any
    recursion: false
    zone: example.com
vantage_answers:
  public_resolver:
    name: app.corp.example.com
    result: NXDOMAIN
  internal_resolver:
    name: app.corp.example.com
    result: 10.24.8.15
ownership_evidence:
  owner: platform-networking
  change_ticket: DNS-1842
expected_classification:
  status: Benign / controlled
  reason: "Private records are scoped to internal clients and public clients cannot recurse or resolve the private name."
```

```yaml
case_id: DNS-SPLIT-02
title: Conditional forwarder sends private suffixes to public resolvers
platform: BIND
conditional_forwarders:
  - suffix: corp.example.com
    forward_to:
      - 8.8.8.8
      - 1.1.1.1
    mode: forward first
protective_dns:
  provider: enterprise-resolver.internal
  receives_private_suffix: false
resolver_logs:
  private_query_observed_by_public_resolver: true
expected_classification:
  status: Conditional forwarder bypass
  severity: High
  reason: "Private names can leak to public resolvers and bypass enterprise logging/filtering."
```

```yaml
case_id: DNS-SPLIT-03
title: Public vantage point receives internal address record
platform: Route53
public_answers:
  - name: admin.example.com
    resolver: 9.9.9.9
    answer: 10.12.4.20
private_zone_expected: true
public_zone_records:
  accidental_rfc1918_record: true
expected_classification:
  status: Public private-record exposure
  severity: High
  reason: "An internal-only address is visible from public resolvers."
```

```yaml
case_id: DNS-SPLIT-04
title: Public and private answers drift without owner evidence
platform: Mixed
record: api.example.com
vantage_answers:
  public_resolver:
    answer: api-prod.example.net
    ttl: 300
  internal_resolver:
    answer: 10.24.8.15
    ttl: 86400
required_evidence:
  owner: missing
  certificate_expectation: missing
  service_inventory: missing
  change_ticket: missing
expected_classification:
  status: Split-horizon drift
  severity: Medium
  reason: "Different answers may be intentional, but ownership and change-control evidence are missing."
```

```yaml
case_id: DNS-SPLIT-05
title: Route 53 private hosted zone has explicit VPC scope
platform: Route53
private_hosted_zone:
  zone: corp.example.com
  associated_vpcs:
    - vpc-0123456789abcdef0
public_vantage:
  name: db.corp.example.com
  result: NXDOMAIN
vpc_vantage:
  name: db.corp.example.com
  result: 10.40.2.19
resolver_rule:
  forwards_to_protective_dns: true
expected_classification:
  status: Benign / controlled
  reason: "Private hosted zone association and query evidence prove the record is only visible inside the intended VPC."
```

```yaml
case_id: DNS-SPLIT-06
title: CoreDNS forwarder can fail open to public upstream
platform: CoreDNS
corefile:
  zone: corp.example.com
  forward_chain:
    - to: 10.30.0.10
      policy: sequential
    - to: 8.8.8.8
      condition: fallback
private_suffix: corp.example.com
protective_dns:
  enforced_on_fallback: false
expected_classification:
  status: Conditional forwarder bypass
  severity: High
  reason: "Fallback can send private suffix lookups to a public resolver when the private upstream is unavailable."
```

```yaml
case_id: DNS-SPLIT-07
title: VPN DNS suffix route evidence is missing
platform: VPN
claimed_private_zone: corp.example.com
client_population:
  vpn_users: expected
evidence:
  vpn_dns_suffix_routes: missing
  client_resolver_config: missing
  internal_query_sample: missing
  public_query_sample: present
expected_classification:
  status: Not evaluable
  reason: "The review cannot prove whether VPN clients receive the private view without effective client routing and query evidence."
```
