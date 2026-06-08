---
name: iac-security
description: >
  Performs a security review of Infrastructure as Code templates against the OWASP
  IaC Security Cheat Sheet, SLSA v1.0, and CIS Benchmarks. Auto-invoked when
  reviewing Terraform, CloudFormation, or Pulumi configurations. Detects hardcoded
  secrets, public exposure patterns, encryption gaps, overly permissive IAM, and
  misconfigurations equivalent to Checkov, tfsec, and KICS rules. Produces a
  structured findings report with remediation guidance. Includes checks for remote
  module immutability and registry trust gates.
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

The review covers nine security domains: secrets management, public exposure, encryption, IAM and access control, logging, network security, supply chain integrity, resource hardening, and module integrity. Each finding is mapped to a specific policy rule equivalent from Checkov, tfsec, or KICS.

## Security Domains

1. Secrets Management
2. Public Exposure
3. Encryption
4. IAM and Access Control
5. Logging
6. Network Security
7. Supply Chain Integrity
8. Resource Hardening
9. Module Integrity

## Module Integrity Checks

* Verify remote module sources use immutable references (e.g., specific commit hashes or tags)
* Validate registry namespace ownership and trust
* Check for provider and module checksum locks
* Detect private registry ownership and mirror provenance
* Identify drift between plan source and apply source

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

- Reviewing Terraform plans or modules before merge or deployment
- Auditing CloudFormation templates for security misconfigurations
- Evaluating Pulumi configurations for security best practices
- Assessing Bicep templates for security compliance