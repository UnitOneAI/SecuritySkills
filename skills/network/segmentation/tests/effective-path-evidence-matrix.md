# Segmentation Effective Path Evidence Fixture

Use this fixture to verify that `segmentation` distinguishes route reachability, policy reachability, and tested effective access before assigning pass/fail conclusions.

## Scenario

The reviewer receives partial cloud and Kubernetes artifacts for three zone boundaries.

### 1. Peering With Restricted DNS Flow

```hcl
resource "aws_vpc_peering_connection" "shared_services" {
  vpc_id       = aws_vpc.app.id
  peer_vpc_id = aws_vpc.shared.id
}

resource "aws_security_group_rule" "app_to_dns" {
  type        = "egress"
  protocol    = "udp"
  from_port   = 53
  to_port     = 53
  cidr_blocks = ["10.50.10.0/24"]
}
```

Expected handling:

- Do not classify peering alone as a segmentation failure.
- Record route tables, security group rules, NACLs, shared-service DNS role, and flow-log/test evidence.
- Assign Low or Medium confidence if the route table or flow evidence is missing.

### 2. Route-Policy Mismatch

```text
App subnet route table:
  10.30.0.0/16 -> transit-gateway

Security group:
  egress only tcp/443 to proxy

Firewall policy:
  deny user -> data

Route table:
  user -> data via local route, bypassing firewall
```

Expected handling:

- Separate "routable path exists" from "authorized flow is effectively allowed".
- Record whether the packet traverses the firewall, transit gateway, local route, or another PEP.
- Use `NE-PEP` or `NE-ROUTE` when the actual enforcement point cannot be identified.

### 3. Kubernetes NetworkPolicy Without Enforcement Evidence

```yaml
kind: NetworkPolicy
metadata:
  namespace: payments
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
```

Expected handling:

- Treat the NetworkPolicy object as policy evidence, not proof of enforcement.
- Require CNI plugin and enforce-mode evidence before marking namespace isolation as pass.
- Use `NE-CNI` when CNI enforcement is unknown and `NE-TEST` when packet or flow testing is stale or missing.

## Expected Report Elements

The final report should include:

| Section | Required Evidence |
|---------|-------------------|
| Effective Segmentation Path Matrix | Source/destination zone, flow, route path, PEP traversed, effective policy, bypass checks, test evidence, freshness, confidence |
| Evidence Gaps / Not Evaluable Boundaries | Missing route, policy, PEP, CNI, mesh, test, flow-log, or PCI dependency reason codes |
| Findings | Severity, confidence, effective path evidence, freshness, remediation |

Passing behavior means the skill reports only evidence-backed segmentation failures and marks materially incomplete boundaries as Not Evaluable instead of speculative pass/fail.
