# Vulnerable Fixture: Stale CIS Kubernetes v1.9.0 Report

## Container & Kubernetes Security Assessment Report

### Environment

- Repository: example-platform
- Date: 2026-06-03
- Frameworks: CIS Docker Benchmark v1.6.0, CIS Kubernetes Benchmark v1.9.0, NIST SP 800-190
- Files reviewed: 2 Dockerfiles, 12 K8s manifests, 1 Helm chart

### Findings by Domain

| Domain | Framework | Critical | High | Medium | Low | Pass |
|--------|-----------|----------|------|--------|-----|------|
| Control Plane | CIS K8s 1.x-4.x | 0 | 4 | 2 | 0 | 6 |
| Pod Security | CIS K8s 5.2.x | 0 | 1 | 3 | 0 | 8 |

### Expected Skill Behavior

Flag this report because it emits CIS Kubernetes v1.9.0 as current, omits Kubernetes version, omits benchmark source date, omits legacy-baseline rationale, and fails managed control-plane checks without evidence-source status.

