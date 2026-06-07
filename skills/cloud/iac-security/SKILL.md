name: iac-security
description: >
  Performs a security review of Infrastructure as Code templates against the OWASP
  IaC Security Cheat Sheet, SLSA v1.0, and CIS Benchmarks. Auto-invoked when
  reviewing Terraform, CloudFormation, or Pulumi configurations. Detects hardcoded
  secrets, public exposure patterns, encryption gaps, overly permissive IAM, and
  misconfigurations equivalent to Checkov, tfsec, and KICS rules. Produces a
  structured findings report with remediation guidance.
tags: [cloud, iac, terraform, cloudformation]
role: [cloud-security-engineer, security-engineer, devsecops]
phase: [build, review]
frameworks: [OWASP-IaC-Security, SLSA-v1.0, CIS-Benchmarks]
difficulty: intermediate
time_estimate: "45-90min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Infrastructure as Code Security Review

## Overview

This skill performs a structured security review of Infrastructure as Code (IaC) templates covering Terraform, CloudFormation, Pulumi, and Bicep. It identifies security anti-patterns, misconfigurations, and policy violations by applying checks equivalent to those performed by static analysis tools (Checkov, tfsec, KICS, cfn-nag) while grounding findings in established frameworks: the OWASP Infrastructure as Code Security Cheat Sheet, SLSA v1.0 supply chain integrity requirements, and relevant CIS Benchmarks.

The review covers eight security domains: secrets management, public exposure, encryption, IAM and access control, logging, network security, supply chain integrity, and resource hardening. Each finding is mapped to a specific policy rule equivalent from Checkov, tfsec, or KICS.

## Security Gates

The following security gates are evaluated during the review:
- Backend encryption: Verify that the state backend is encrypted.
- Access policy: Check if the access policy for the state backend is restrictive.
- Public access block: Ensure that public access to the state backend is blocked.
- Versioning: Confirm that versioning is enabled for the state backend.
- Lock table: Verify that a lock table is used to prevent concurrent modifications.
- State secret minimization: Check if sensitive values are stored in the state.
- Drift detection cadence: Evaluate the frequency of drift detection.
- State read and apply permissions: Verify that only authorized users can read and apply changes to the state.

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

- Reviewing Terraform plans or modules before merge or deployment
- Auditing CloudFormation templates for security misconfigurations
- Evaluating Pulumi configurations for security best practices
- Assessing Bicep templates for security compliance

## False Positive Analysis

Benign configurations that may be over-flagged include:
- Terraform state backends with restricted IAM and versioning
- CloudFormation templates with secure access policies

## Coverage Gaps

The review may not catch the following variants:
- Unencrypted state backends with public access
- Sensitive values stored in the state without proper encryption
- Inadequate drift detection and remediation

## Edge Cases

A plan can pass IaC policy checks while the remote state backend is the real exposure path. Sensitive values, stale drift, and unlocked state can undermine otherwise secure resources.

## Remediation Quality

- [x] Fix resolves the vulnerability
- [x] Fix doesn't introduce new security issues
- [x] Fix doesn't break functionality
- **Issues found:** Add gates for backend encryption, access policy, public access block, versioning, lock table, state secret minimization, drift detection cadence, and who can read state versus apply changes.

## Comparison to Other Tools

| Tool | Catches this? | Notes |
|------|---------------|-------|