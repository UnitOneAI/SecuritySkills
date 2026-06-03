# Benign Fixture: CIS Kubernetes v2.0.0 Evidence-Scoped Report

## Container & Kubernetes Security Assessment Report

### Environment

- Repository: example-platform
- Date: 2026-06-03
- Kubernetes version: 1.35
- Distribution/provider: EKS
- Frameworks: CIS Docker Benchmark v1.6.0, CIS Kubernetes Benchmark v2.0.0, NIST SP 800-190
- Legacy mode: No
- Benchmark source date: 2026-05-18
- Evidence sources: manifest, rendered-helm, kube-bench/AAC, provider-api
- Files reviewed: 2 Dockerfiles, 12 K8s manifests, 1 Helm chart

### Findings by Domain

| Domain | Framework | Critical | High | Medium | Low | Pass |
|--------|-----------|----------|------|--------|-----|------|
| Control Plane | CIS K8s 1.x-4.x | 0 | 0 | 0 | 0 | Provider Managed |
| Worker Nodes | CIS K8s 4.x | 0 | 1 | 1 | 0 | 8 |
| Pod Security | CIS K8s 5.x | 0 | 1 | 3 | 0 | 8 |

### Detailed Finding

#### [CIS-K8S v2.0.0 / Section 5 Policies] Namespace missing restricted PSA enforce label

- Status: Fail
- Severity: High
- Benchmark Version: CIS Kubernetes v2.0.0
- Evidence Source: rendered Helm
- Cluster Scope: managed-provider
- File: `charts/app/templates/namespace.yaml`
- Resource: `Namespace/production`
- Description: Namespace has `pod-security.kubernetes.io/audit=restricted` but no `pod-security.kubernetes.io/enforce=restricted`.
- Remediation: Add the restricted enforce label or document an approved exception.

