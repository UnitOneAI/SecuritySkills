# IPv6 Parity and Temporary Rule Fixtures

These fixtures calibrate the supplemental `FW-IPV6-*` and `FW-TEMP-*` evidence gates in `firewall-review`.

```yaml
case: ipv6_disabled_not_applicable
platform: aws_security_group
address_family:
  ipv4: enabled
  ipv6: disabled
evidence:
  subnet_assign_ipv6_address_on_creation: false
  ipv6_cidr_block_association: absent
  route_table_ipv6_default_route: absent
  host_ipv6_interfaces: disabled
rules:
  ipv4_ingress_https: restricted_to_load_balancer
  ipv6_rules: template_only_not_attached
expected_decision: Not Applicable
expected_findings: []
```

```yaml
case: reachable_ipv6_ssh_exposure
platform: terraform_aws_security_group
address_family:
  ipv4: restricted
  ipv6: routed
rules:
  ipv4_ssh:
    cidr_blocks:
      - 203.0.113.10/32
  ipv6_ssh:
    from_port: 22
    to_port: 22
    protocol: tcp
    ipv6_cidr_blocks:
      - "::/0"
evidence:
  subnet_ipv6_cidr: present
  internet_gateway_ipv6_route: "::/0"
  logging: missing
expected_decision: Fail
expected_findings:
  - check: FW-IPV6-03
    severity: Critical
    reason: Privileged SSH ingress is restricted for IPv4 but reachable from any IPv6 source.
  - check: FW-IPV6-05
    severity: Medium
    reason: IPv6 allow events are not logged or sent to the SIEM.
```

```yaml
case: iptables_drop_ip6tables_accept
platform: linux_host_firewall
address_family:
  ipv4: enabled
  ipv6: enabled
rules:
  iptables:
    input_policy: DROP
    forward_policy: DROP
    output_policy: DROP
  ip6tables:
    input_policy: ACCEPT
    forward_policy: ACCEPT
    output_policy: ACCEPT
expected_decision: Fail
expected_findings:
  - check: FW-IPV6-02
    severity: Critical
    reason: IPv4 default deny is configured but IPv6 remains default allow.
```

```yaml
case: controlled_ipv6_https_egress_via_proxy
platform: cloud_security_group
address_family:
  ipv4: enabled
  ipv6: enabled_but_no_subnet_assignment
rule:
  id: sg-https-egress-v6
  family: ipv6
  direction: egress
  protocol: tcp
  port: 443
  destination: "::/0"
  justification: outbound web access forced through TLS inspection proxy
  proxy_required: true
  direct_internet_route: absent
  owner: network-security
  change_ticket: CHG-2026-4421
  expires_at: "2026-07-01"
  logging: enabled
expected_decision: Pass
expected_findings: []
```

```yaml
case: unrestricted_ipv6_egress_with_restrictive_ipv4
platform: terraform_aws_security_group
address_family:
  ipv4: controlled
  ipv6: routed
rules:
  ipv4_egress:
    cidr_blocks:
      - 10.10.0.53/32
    ports:
      - 53
  ipv6_egress:
    protocol: "-1"
    ipv6_cidr_blocks:
      - "::/0"
evidence:
  proxy_enforcement: missing
  logging: missing
expected_decision: Fail
expected_findings:
  - check: FW-IPV6-04
    severity: High
    reason: IPv4 egress is restricted but IPv6 egress allows all protocols to the internet.
```

```yaml
case: expired_temporary_database_access
platform: firewall_rulebase
rule:
  id: TEMP-incident-allow-db
  source: 10.40.0.0/16
  destination: db-prod-01
  port: 5432
  action: allow
  comment: temporary incident access
  owner: null
  change_ticket: null
  created_at: "2026-05-01"
  expires_at: null
  last_reviewed: unknown
  compensating_controls: missing
expected_decision: Fail
expected_findings:
  - check: FW-TEMP-01
    severity: High
    reason: Temporary database access lacks owner, business justification, and change ticket evidence.
  - check: FW-TEMP-02
    severity: High
    reason: Temporary access has no expiry, review date, renewal, or removal plan.
```

```yaml
case: zero_hit_rule_after_counter_reset
platform: next_generation_firewall
rule:
  id: allow-partner-api
  source: partner-vpn
  destination: api-prod
  port: 443
  action: allow
  hit_count: 0
  counter_reset_at: "2026-06-05T23:30:00Z"
  review_started_at: "2026-06-06T01:00:00Z"
dependency_evidence:
  flow_logs_lookback_days: missing
  asset_owner_confirmation: missing
  rollback_plan: missing
expected_decision: Not Evaluable
expected_findings:
  - check: FW-TEMP-03
    severity: Medium
    reason: Zero-hit rule cannot be safely removed because counters were recently reset and dependency evidence is missing.
```
