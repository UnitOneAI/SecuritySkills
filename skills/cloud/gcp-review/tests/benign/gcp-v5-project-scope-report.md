# Benign: GCP v5 Project Scope Report

## GCP Security Posture Assessment Report

### Environment

- Project ID: `prod-project-1`
- Folder ID: `not supplied`
- Organization ID: `1234567890`
- Date: 2026-06-03
- Framework: CIS Google Cloud Platform Foundation Benchmark v5.0.0
- Benchmark source date: 2026-05-09
- Legacy baseline: false
- Scope level: Mixed
- Evidence sources: Security Command Center, Cloud Asset Inventory, Terraform
- Files reviewed: `scc/cis-v5-findings.json`, `terraform/gcp/*.tf`, `org-policies/default-network.yaml`

### Executive Summary

- Total current benchmark controls evaluated: 48/48 from supplied CIS v5 benchmark export
- Project-level passed: 44
- Project-level failed: 4
- Organization-context findings: 3, not counted unless mapped to selected benchmark scope
- Folder-context findings: 0
- Legacy controls: 0
- Not Applicable: 0
- Not Evaluable: 0
- Overall current benchmark compliance: 92%

### Scope Scores

| Scope | Evidence Source | Scope Status | Passed | Failed | N/A | Not Evaluable | Compliance |
|-------|-----------------|--------------|--------|--------|-----|---------------|------------|
| Project IAM/KMS/API keys | SCC + Terraform | Current v5 Project Scope | 12 | 1 | 0 | 0 | 92% |
| Project logging/monitoring | Cloud Asset + Terraform | Current v5 Project Scope | 10 | 1 | 0 | 0 | 91% |
| Project network/compute | SCC + Terraform | Current v5 Project Scope | 14 | 2 | 0 | 0 | 88% |
| Project data services | SCC + Terraform | Current v5 Project Scope | 8 | 0 | 0 | 0 | 100% |
| Organization context | Org policy export | Organization Context | 0 | 0 | 0 | 0 | not in project score |

### Detailed Findings

#### [Scope:Organization] Default network creation policy

- **Status:** Pass as organization context
- **Scope Status:** Organization Context
- **Benchmark Version:** CIS Google Cloud Platform Foundation Benchmark v5.0.0
- **Evidence Source:** Organization policy export
- **Description:** Organization policy disables default network creation, but this is recorded separately from project-level score unless mapped by the selected benchmark export.
