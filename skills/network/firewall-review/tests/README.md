# Firewall Review Evidence Fixtures

These fixtures exercise the IPv6 parity and temporary-rule governance gates in `firewall-review`.

Use the benign cases to verify false-positive reduction:

- `benign/controlled-ipv6-egress-proxy.md` shows broad-looking IPv6 HTTPS egress that is acceptable only when proxy, routing, owner, ticket, logging, and expiry evidence are present.
- `benign/ipv6-disabled-not-applicable.md` shows the evidence required before marking IPv6 checks as `Not Applicable`.

Use the vulnerable cases to verify coverage expansion:

- `vulnerable/ip6tables-default-accept.md` catches IPv4 default deny with IPv6 default allow.
- `vulnerable/ssh-ipv6-anywhere.md` catches privileged `::/0` ingress in cloud security groups.
- `vulnerable/unrestricted-ipv6-egress.md` catches IPv6 all-protocol egress when IPv4 egress is restricted.
- `vulnerable/temporary-db-permit-no-expiry.md` catches temporary access without owner, ticket, expiry, or review evidence.
