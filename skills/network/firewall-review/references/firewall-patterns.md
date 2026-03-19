# Firewall Platform-Specific Pattern Examples

Extracted from the firewall-review SKILL.md.

## iptables

```bash
# Default policy should be DROP
:INPUT DROP
:FORWARD DROP
:OUTPUT DROP

# Any/any accept (BAD)
-A INPUT -j ACCEPT

# Missing LOG target before DROP (BAD)
-A INPUT -j DROP

# Logged then dropped (GOOD)
-A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4
-A INPUT -j DROP
```

## Cisco ASA

```
# Overly permissive (BAD)
permit ip any any

# Shadowed rule pattern
# Rule 10: permit tcp any any eq 443        (broad)
# Rule 25: permit tcp 10.0.1.0/24 any eq 443  (shadowed by Rule 10)
```

## Terraform (AWS Security Groups)

```hcl
# Overly permissive ingress (BAD)
ingress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# Default action Allow (BAD)
default_action = "Allow"    # Should be "Deny"
```

## Palo Alto

```
# Logging disabled (BAD)
log-end: no

# Logging enabled (GOOD)
log-end: yes
```

## Cloud Security Groups

```
# Unrestricted egress (BAD -- common default in AWS)
egress: 0.0.0.0/0 allow all

# Overly permissive (BAD)
from_port: 0
to_port: 65535
cidr_blocks: ["0.0.0.0/0"]
```
