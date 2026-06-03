# Benign: Azure v6 Report with Entra Boundary

## Azure Security Posture Assessment Report

### Environment

- Subscription/Repository: example-platform
- Date: 2026-06-03
- Framework: CIS Microsoft Azure Foundations Benchmark v6.0.0
- Benchmark source date: 2026-05
- Legacy baseline: false
- Entra scope handling: excluded
- Evidence sources: Defender for Cloud, Azure Policy, Terraform
- Files reviewed: `defender/cis-v6-export.json`, `terraform/azure/*.tf`, `entra/conditional-access.json`

### Executive Summary

- Total Azure Foundations controls evaluated: 42/42 from supplied CIS v6 benchmark export
- Passed: 39
- Failed: 3
- Entra/M365 scoped findings: 4, excluded from Azure score
- Legacy controls: 0
- Deleted or migrated controls: 0
- Not Applicable: 0
- Not Evaluable: 0
- Overall Azure Foundations compliance: 93%

### Section Scores

| Control Family | Evidence Source | Scope Status | Passed | Failed | N/A | Not Evaluable | Compliance |
|----------------|-----------------|--------------|--------|--------|-----|---------------|------------|
| Defender/Azure Policy | Defender for Cloud | Current Azure v6 Scope | 8 | 1 | 0 | 0 | 89% |
| Storage/Data | Terraform + Azure Policy | Current Azure v6 Scope | 10 | 1 | 0 | 0 | 91% |
| Logging/Monitoring | Azure Monitor export | Current Azure v6 Scope | 7 | 0 | 0 | 0 | 100% |
| Network/Compute | Terraform | Current Azure v6 Scope | 8 | 1 | 0 | 0 | 89% |
| Key Vault/App Service | Terraform | Current Azure v6 Scope | 6 | 0 | 0 | 0 | 100% |
| Entra/M365 | Entra export | Excluded | 0 | 0 | 0 | 0 | not in Azure score |

### Detailed Findings

#### [Scope:Entra/M365] Conditional Access MFA policy

- **Status:** Not Evaluable for Azure Foundations
- **Scope Status:** Entra/M365 Scope
- **Benchmark Version:** CIS Microsoft Azure Foundations Benchmark v6.0.0
- **Evidence Source:** Entra Conditional Access export
- **Description:** Entra evidence was present but excluded from Azure Foundations scoring because Microsoft 365/Entra scope was not requested.
