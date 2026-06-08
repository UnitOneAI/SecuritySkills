---
name: segmentation
description: >
  Performs a structured network segmentation review against NIST SP 800-207
  (Zero Trust Architecture) and CIS Controls v8 (Control 12 -- Network
  Infrastructure Management). Auto-invoked when reviewing network architecture,
  VLAN configurations, micro-segmentation policies, or DMZ designs. Produces a
  segmentation maturity assessment with zone mapping, trust boundary analysis,
  and remediation guidance.
tags: [network, segmentation, micro-segmentation]
role: [security-engineer, architect]
phase: [design, operate]
frameworks: [NIST-SP-800-207, CIS-Controls-v8]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Network Segmentation Review

A structured, repeatable process for evaluating network segmentation architecture against NIST SP 800-207 (Zero Trust Architecture) and CIS Controls v8 Control 12 (Network Infrastructure Management). This skill produces a segmentation maturity assessment with zone mapping, trust boundary analysis, east-west traffic control evaluation, and prioritized remediation guidance.

## Gates
The following gates must be evaluated during the review:
- **Service Mesh Bypass**: Verify that pods are not running with hostNetwork or hostPort, which could bypass service mesh sidecar policy.
- **Default Deny Network Policy**: Check if a default-deny NetworkPolicy is in place to restrict traffic that bypasses the sidecar or targets non-mesh workloads.
- **MTLS Strictness**: Evaluate the strictness of mTLS configuration to ensure it is set to STRICT.
- **Sidecar Injection Coverage**: Verify that sidecar injection is enabled and required for all pods.
- **CNI Enforcement Status**: Check the status of CNI enforcement to ensure it is enabled and effective.
- **Node-Local Bypass Paths**: Identify and evaluate node-local bypass paths that could be used to reach protected zones.
- **Exception Expiry**: Verify that exceptions have explicit owners, expiry dates, and evidence that host-level routes cannot reach protected zones.

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

- Architecture reviews for new or modified network designs.
- Zero Trust readiness assessments.
- PCI DSS scoping exercises requiring CDE segmentation validation (PCI DSS v4.0 Requirement 1.3).
- Post-incident reviews where lateral movement was observed or suspected.
- Cloud migration planning requiring workload isolation design.
- Merger/acquisition network integration planning.

## Context

Network segmentation is the foundational control that limits blast radius. NIST SP 800-207 Section 2 defines Zero Trust Architecture as requiring "no implicit trust granted to assets or user accounts based solely on their physical or network location."

## Evaluation Criteria

The following criteria will be used to evaluate the network segmentation architecture:
- **Zone Mapping**: Identify and map zones based on trust boundaries and network segmentation.
- **Trust Boundary Analysis**: Analyze trust boundaries to identify potential weaknesses and vulnerabilities.
- **East-West Traffic Control**: Evaluate east-west traffic control mechanisms to ensure they are effective and properly configured.
- **Remediation Guidance**: Provide prioritized remediation guidance based on the evaluation results.

## False Positive Analysis

Benign code/config that can be over-flagged: