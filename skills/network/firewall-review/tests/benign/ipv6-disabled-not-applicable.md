# Benign: IPv6 Disabled With Not Applicable Evidence

## Fixture

```yaml
scope: prod-web-subnet-a
ipv6_status:
  host_interfaces:
    eth0_accept_ra: 0
    eth0_ipv6_addresses: []
  subnet_ipv6_assignment: disabled
  vpc_ipv6_cidr: null
  route_table_ipv6_default_route: null
  security_group_ipv6_rules: []
evidence:
  host_command: "sysctl net.ipv6.conf.eth0.disable_ipv6=1"
  cloud_subnet: "assignIpv6AddressOnCreation=false"
  route_table: "no ::/0 route"
  reviewed_at: 2026-06-05
```

## Expected Result

Report IPv6 as `Not Applicable`, not as a vulnerability, because host, subnet, and route-table evidence all prove IPv6 is disabled or unrouted.

If any layer is unknown, report `Not Evaluable` instead of assuming IPv4-only coverage.
