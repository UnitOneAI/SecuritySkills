# Compensating Control Evaluation Matrix

Extracted from the patch-prioritization SKILL.md.

| Control Type | Example | Effectiveness Criteria | Max SLA Extension |
|---|---|---|---|
| **Network segmentation** | VLAN isolation, firewall rules blocking attack vector port/protocol | Prevents network path to vulnerable service; verified by scan | +14 days for P2/P3 |
| **WAF/IPS rule** | Virtual patch rule targeting specific CVE exploit pattern | Rule tested against known PoC; bypass testing performed | +7 days for P1/P2 |
| **Feature/service disabled** | Vulnerable component disabled or uninstalled | Component confirmed absent from runtime configuration | Reclassify to P4 or close |
| **EDR/XDR detection** | Behavioral detection for exploitation indicators | Detection rule tested; alert routing confirmed | +7 days for P2 only |
| **Access restriction** | MFA requirement, IP allowlisting, privilege reduction | Attack requires access that is now gated | +7 days for P2/P3 |

## Validation Criteria

For each compensating control claimed, validate:

1. **Control effectiveness:** Does the control directly address the specific attack vector of the CVE?
2. **Control coverage:** Does the control protect all affected assets, or only a subset?
3. **Control durability:** Is the control persistent (e.g., network ACL) or ephemeral (e.g., manual process)?
4. **Control verification:** Can the control's effectiveness be independently verified or tested?
5. **Residual risk:** What risk remains after the compensating control is applied?
