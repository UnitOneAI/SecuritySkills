---
name: secrets-management
description: >
  Performs a structured secrets management review against OWASP Secrets
  Management Cheat Sheet and NIST SP 800-57 Part 1 Rev 5 (Recommendation for
  Key Management). Auto-invoked when reviewing secret handling patterns, vault
  configurations, .env files, or credential rotation policies. Produces a secrets
  management assessment covering detection patterns, rotation automation, vault
  integration, and agent-specific credential handling.
tags: [devsecops, secrets, vault, rotation]
role: [security-engineer, devsecops]
phase: [build, operate]
frameworks: [OWASP-Secrets-Management, NIST-SP-800-57-Part1-Rev5]
difficulty: intermediate
time_estimate: "20-40min"
version: "1.0.1"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Secrets Management Review

A structured, repeatable process for evaluating secrets management practices against the OWASP Secrets Management Cheat Sheet and NIST SP 800-57 Part 1 Rev 5 (Recommendation for Key Management). This skill covers secret detection patterns, rotation automation, vault and cloud secrets manager integration, agent-specific credential handling, .env file exposure, and git history secret leaks. All findings reference framework controls with severity ratings and actionable remediation.

**Important:** This skill analyzes detection patterns and configuration practices. It never extracts, logs, or displays actual secret values. All regex patterns shown are for detection tooling configuration, not for secret extraction.

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

- Security review of application repositories for hardcoded credentials.
- Evaluation of secrets management architecture (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault).
- CI/CD pipeline credential hygiene assessment.

## Review Checklist

1. **Secret Zero**: Verify the presence of a secure bootstrap secret (e.g., OIDC token, client certificate) for initial authentication.
2. **Workload Identity**: Ensure workload identity is enabled and properly configured to limit access to secrets.
3. **Secret Rotation**: Verify automated secret rotation is in place, including rotation policies and schedules.
4. **Vault Configuration**: Review vault configuration for proper access controls, encryption, and auditing.
5. **Bootstrap Token**: Verify the bootstrap token has a limited time-to-live (TTL) and is properly rotated.
6. **Recovery and Break-Glass**: Ensure recovery and break-glass procedures are in place, including secure storage of recovery credentials.
7. **Rotation Test Evidence**: Verify rotation test evidence is available, including logs and audit trails.
8. **Revocation**: Ensure revocation procedures are in place for compromised or expired secrets.

## Evidence Gates

To ensure the security of secrets management, the following evidence gates must be met:

1. **Secret Zero Source**: Provide evidence of a secure bootstrap secret source.
2. **Workload Identity Constraints**: Provide evidence of workload identity constraints, such as limited access to secrets.
3. **Bootstrap Token TTL**: Provide evidence of a limited TTL for the bootstrap token.
4. **Recovery and Break-Glass Custody**: Provide evidence of secure storage of recovery and break-glass credentials.
5. **Rotation Test Evidence**: Provide evidence of rotation test results, including logs and audit trails.
6. **Revocation After Failed Bootstrap Attempts**: Provide evidence of revocation procedures for compromised or expired secrets.

By including these evidence gates, reviewers can ensure that secrets management practices are secure and compliant with industry standards.