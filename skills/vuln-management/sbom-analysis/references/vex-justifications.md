# VEX Justification Categories

Extracted from the sbom-analysis SKILL.md.

## VEX Status Types

| VEX Status | Definition | Action Required |
|---|---|---|
| **Not Affected** | The product is not affected by the vulnerability. Must include justification. | No remediation required. Document the justification for audit trail. |
| **Affected** | The product is affected by the vulnerability. | Remediate per SLA tier. |
| **Fixed** | The vulnerability was present but has been remediated in this version. | Verify the fixed version is deployed. |
| **Under Investigation** | The vendor is still assessing whether the product is affected. | Monitor for updated VEX statement. Apply precautionary controls if critical path. |

## "Not Affected" Justification Categories (CSAF VEX)

| Justification | Meaning | Validation Approach |
|---|---|---|
| **component_not_present** | The vulnerable component is not included in the product | Verify against SBOM component list |
| **vulnerable_code_not_present** | The component is present but the specific vulnerable code path is not included | Requires vendor attestation or code analysis |
| **vulnerable_code_not_in_execute_path** | The vulnerable code exists but cannot be reached during execution | Requires call-graph or runtime analysis |
| **vulnerable_code_cannot_be_controlled_by_adversary** | The vulnerable code is present and reachable but attacker-controlled input cannot reach it | Requires threat model or data-flow analysis |
| **inline_mitigations_already_exist** | Built-in mitigations (ASLR, sandboxing, etc.) prevent exploitation | Verify mitigations are active and effective |
