# Firewall Rule Lifecycle Edge Cases

These fixtures validate that firewall-review checks the governance lifecycle of
rules, not only packet-matching logic.

## Edge Case 1: Expired Emergency Rule Still Active

Input evidence:

```yaml
rule_id: fw-443-admin-temp
source: 0.0.0.0/0
destination: admin-jumpbox
port: 443
action: allow
description: "temporary incident access IR-2026-041"
ticket: IR-2026-041
owner: platform-security
expiry: "2026-05-30"
current_date: "2026-06-06"
logging_enabled: true
```

Expected output:

- Finding ID: `FW-LIFE-02`
- Severity: High because the rule is internet-facing and expired
- Remediation requires removal or renewed risk acceptance with owner and expiry

## Edge Case 2: Zero Hit Count With Recent Counter Reset

Input evidence:

```yaml
rule_id: fw-dr-replication
source: dr-subnet
destination: prod-db
port: 5432
action: allow
hit_count: 0
counter_reset_at: "2026-06-05T22:00:00Z"
review_started_at: "2026-06-06T09:00:00Z"
business_context: quarterly_dr_test
rollback_plan: missing
```

Expected output:

- Do not classify as unused based on hit count alone
- Finding ID: `FW-LIFE-04` if removal is recommended without dependency validation
- Require flow logs, owner confirmation, and rollback plan

## Edge Case 3: IaC Drift From Cloud Console Rule

Input evidence:

```yaml
iac_rule:
  rule_id: sg-web-egress
  egress: deny_all_except_proxy
deployed_rule:
  rule_id: sg-web-egress-console-override
  egress: allow_all
  source_of_change: console
  ticket: null
  approver: null
```

Expected output:

- Finding ID: `FW-LIFE-08`
- Severity: High because deployed egress is allow-all and not in source control
- Remediation reconciles deployed state back to IaC and reviews change path
