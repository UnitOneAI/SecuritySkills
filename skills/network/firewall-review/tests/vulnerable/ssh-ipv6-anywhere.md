# Vulnerable: Privileged IPv6 Ingress From Anywhere

## Fixture

```hcl
resource "aws_security_group_rule" "ssh_ipv6_anywhere" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.admin.id
  description       = "temporary admin access"
}

resource "aws_security_group_rule" "ssh_ipv4_corp_only" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["203.0.113.0/24"]
  security_group_id = aws_security_group.admin.id
}
```

## Expected Result

Flag as `Critical` when IPv6 is routable because SSH is exposed from `::/0` even though the IPv4 peer is limited to a corporate CIDR.

The `temporary admin access` description must not reduce severity without owner, change-ticket, expiry, and review evidence.
