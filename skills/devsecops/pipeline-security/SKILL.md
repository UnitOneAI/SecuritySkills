---
name: pipeline-security
description: >
  Reviews CI/CD pipeline configurations against SLSA v1.0 build levels and
  OWASP Top 10 CI/CD Security Risks. Auto-invoked when reviewing GitHub Actions
  workflows, GitLab CI configs, Jenkins pipelines, or when discussing supply
  chain security. Produces a pipeline security assessment with SLSA level
  determination and CICD-SEC risk findings.
tags: [devsecops, cicd, pipeline, supply-chain]
role: [security-engineer, devsecops]
phase: [build, deploy]
frameworks: [SLSA-v1.0, OWASP-CICD-Top-10]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Pipeline Security Assessment

## Overview

If a target is provided via arguments, focus the review on: $ARGUMENTS

This skill performs a structured security review of CI/CD pipeline configurations against two industry-standard frameworks:

- **SLSA v1.0** (Supply-chain Levels for Software Artifacts) -- Build level determination per slsa.dev specifications.
- **OWASP Top 10 CI/CD Security Risks** -- Systematic evaluation against all ten CICD-SEC controls defined by the OWASP CI/CD Security project.

The assessment produces a formal report containing a SLSA build level determination, per-control CICD-SEC findings, and prioritized remediation guidance.

## Objectives

1. Determine the repository's current SLSA Build Level (L1, L2, or L3).
2. Evaluate pipeline configurations against each of the ten OWASP CICD-SEC risk categories.
3. Identify concrete misconfigurations, insecure patterns, and missing controls.
4. Deliver prioritized, actionable remediation steps with control IDs.

## Prerequisites

- Access to CI/CD configuration files (e.g., `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `cloudbuild.yaml`).
- Access to repository settings context (branch protection, permissions).

## Review Checklist

### SLSA v1.0 Build Level Determination

1. **Source Code**: Is the source code stored in a version control system?
2. **Build Configuration**: Is the build configuration defined in a file (e.g., `Dockerfile`, `build.gradle`)?
3. **Build Process**: Is the build process automated and reproducible?
4. **Artifact Storage**: Are artifacts stored in a secure and tamper-evident manner?

### OWASP Top 10 CI/CD Security Risks

1. **Insecure Pipeline Configuration**: Are pipeline configurations properly secured (e.g., no hardcoded secrets)?
2. **Insufficient Access Control**: Are access controls in place to restrict pipeline execution and modification?
3. **Inadequate Logging and Monitoring**: Are logs and monitoring in place to detect and respond to security incidents?
4. **Vulnerable Dependencies**: Are dependencies up-to-date and free from known vulnerabilities?
5. **Insecure Data Storage**: Are sensitive data (e.g., credentials, encryption keys) properly secured?
6. **Insufficient Network Segmentation**: Are network segments properly isolated to prevent lateral movement?
7. **Inadequate Secrets Management**: Are secrets properly managed and rotated?
8. **Insecure Artifact Storage**: Are artifacts stored in a secure and tamper-evident manner?
9. **Insufficient Supply Chain Risk Management**: Are supply chain risks properly assessed and mitigated?
10. **Inadequate Incident Response**: Is an incident response plan in place to respond to security incidents?

## Additional Checks for Self-Hosted Runners

1. **Runner Ephemerality**: Are self-hosted runners ephemeral and wiped after each use?
2. **Workspace Cleanup**: Are workspaces properly cleaned up after each job execution?
3. **Secret Exposure**: Are secrets properly secured and not exposed to unauthorized parties?
4. **Network Segmentation**: Are self-hosted runners properly isolated from sensitive networks?
5. **Pull Request Target**: Are pull request targets properly validated and secured?
6. **Label Trust Boundaries**: Are label trust boundaries properly defined and enforced?
7. **Artifact/Cache Poisoning**: Are artifacts and caches properly secured to prevent poisoning?

## Remediation Guidance

Based on the findings, provide prioritized and actionable remediation steps to address identified security risks and misconfigurations.