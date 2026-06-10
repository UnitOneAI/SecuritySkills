# Benign: Controlled IPv6 HTTPS Egress Through Proxy

## Fixture

```yaml
rule_id: sg-https-egress-v6
family: ipv6
direction: egress
protocol: tcp
port: 443
destination: "::/0"
action: allow
proxy_required: true
proxy_address: 2001:db8:10:40::20
subnet_ipv6_assignment: disabled
direct_internet_route: false
flow_logs_enabled: true
owner: network-security
change_ticket: CHG-2026-4421
created_at: 2026-06-01
expires_at: 2026-07-01
last_reviewed: 2026-06-05
```

## Expected Result

No finding when the review evidence proves IPv6 is not directly routable and HTTPS egress is forced through an inspected proxy with owner, ticket, logging, and expiry evidence.

If any of `direct_internet_route: false`, `proxy_required: true`, `owner`, `change_ticket`, or `expires_at` is missing, downgrade only when compensating evidence is documented.
