# Vulnerable: IPv4 Default Deny With IPv6 Default Accept

## Fixture

```bash
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
```

## Expected Result

Flag as `Critical` when IPv6 is routable. IPv4 default deny does not protect dual-stack hosts when the IPv6 rule base defaults to accept.

If IPv6 reachability is unknown, flag as `High` or `Not Evaluable` according to the available routing and interface evidence.
