# Vulnerable: Unrestricted IPv6 Egress With Restricted IPv4

## Fixture

```hcl
egress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["198.51.100.20/32"]
  description = "approved HTTPS proxy"
}

egress {
  from_port        = 0
  to_port          = 0
  protocol         = "-1"
  ipv6_cidr_blocks = ["::/0"]
  description      = "default IPv6 egress"
}
```

## Expected Result

Flag as `High` when IPv6 is routable. IPv4 egress is constrained to a proxy, but IPv6 allows all protocols to all destinations.

The review should require IPv6 egress parity for DNS, SMTP, HTTPS proxy routing, uncommon protocols, and deny-all cleanup.
