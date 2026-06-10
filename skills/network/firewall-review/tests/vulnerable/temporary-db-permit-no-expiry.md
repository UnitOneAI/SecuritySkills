# Vulnerable: Temporary Database Permit Without Governance Evidence

## Fixture

```yaml
rule_id: TEMP-incident-db-allow
direction: ingress
family: ipv4
source: 10.40.0.0/16
destination: db-prod-01
protocol: tcp
port: 5432
action: allow
comment: temporary incident access
owner: null
change_ticket: null
created_at: 2026-04-15
expires_at: null
last_hit: 2026-06-04T11:20:00Z
last_reviewed: unknown
```

## Expected Result

Flag as `High` when the rule still permits sensitive database access after the incident window without owner, ticket, expiry, or review evidence.

At minimum, missing owner, ticket, expiry, or last review should be reported as a temporary-rule governance failure.
