# Firewall Rule Evidence Matrix Edge Cases

These fixtures verify that `firewall-review` records evidence confidence, object expansion, NAT stage, counter baselines, logging proof, and Not Evaluable reason codes before assigning severity.

```yaml
case_id: FW-EVID-01
title: Private east-west HTTPS rule is controlled with high-confidence evidence
rule:
  id: sg-private-endpoint
  action: allow
  direction: ingress
  source: 10.20.0.0/16
  destination: app-private-endpoint
  service: tcp/443
evidence:
  owner: platform-networking
  ticket: CHG-1842
  logging: siem_query_present
  source_of_truth: terraform
  flow_logs: observed_expected_traffic
expected_classification:
  status: Benign / controlled
  confidence: High
  reason: "Private source, owner/ticket, logging, and flow evidence support the rule."
```

```yaml
case_id: FW-EVID-02
title: Object group hides broad network member
rule:
  id: outside-in-120
  action: allow
  source: any
  destination_object: APP_PROD
  service: tcp/443
object_expansion:
  APP_PROD:
    - 10.0.0.0/8
    - 10.2.3.4/32
expected_classification:
  status: Overly permissive
  severity: High
  confidence: High
  reason: "Expanded object includes a broad private CIDR behind an inbound permit."
```

```yaml
case_id: FW-EVID-03
title: Missing object expansion blocks severity assignment
rule:
  id: outside-in-121
  action: allow
  source: any
  destination_object: TRUSTED_NETS
  service_group: WEB-SVC
object_expansion: missing
service_expansion: missing
expected_classification:
  status: Not Evaluable
  not_evaluable_reason: FW-NE-01
  reason: "Object and service groups must be expanded before judging exposure."
```

```yaml
case_id: FW-EVID-04
title: Hit count reset makes unused-rule conclusion unsafe
rule:
  id: 120
  action: allow
  source: any
  destination: 10.5.10.20
  service: tcp/22
runtime_counters:
  hit_count: 0
  counter_reset: "2026-06-06T16:00:00Z"
  review_window_days: 90
expected_classification:
  status: Not Evaluable
  not_evaluable_reason: FW-NE-02
  reason: "Recent counter reset invalidates zero-hit unused-rule evidence."
```

```yaml
case_id: FW-EVID-05
title: NAT exposes internal service through translated public path
nat:
  original_destination: 203.0.113.10
  original_service: tcp/443
  translated_destination: 10.0.20.15
  translated_service: tcp/8443
security_policy:
  destination: 10.0.20.15
  service: tcp/8443
  action: allow
expected_classification:
  status: Public exposure via NAT
  severity: High
  confidence: High
  reason: "Effective internet-facing path is pre-NAT 203.0.113.10:443 to internal tcp/8443."
```

```yaml
case_id: FW-EVID-06
title: IPv6 policy missing while IPv6 is enabled
platform:
  ipv6_enabled: true
exports:
  ipv4_policy: present
  ipv6_policy: missing
expected_classification:
  status: Not Evaluable
  not_evaluable_reason: FW-NE-04
  reason: "IPv6 policy must be reviewed or explicitly disabled before default-deny can pass."
```

```yaml
case_id: FW-EVID-07
title: Logging flag present but SIEM ingestion proof missing
rule:
  id: db-permit-44
  action: allow
  destination_zone: database
  service: tcp/5432
logging:
  rule_log_end: true
  log_destination: missing
  siem_ingestion: missing
expected_classification:
  status: Not Evaluable
  not_evaluable_reason: FW-NE-08
  reason: "Rule logging flag alone does not prove logs reach a destination or SIEM."
```
