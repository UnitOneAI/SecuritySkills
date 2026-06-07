---
name: detection-engineering
description: >
  Guides creation of detection rules using Sigma rule specification and the
  Palantir Alerting and Detection Strategy (ADS) framework, mapped to MITRE
  ATT&CK v16 techniques. Auto-invoked when the user discusses detection logic,
  Sigma rules, ATT&CK coverage gaps, or asks "how do I detect this technique?"
  Produces Sigma-formatted detection rules, ADS documentation, and coverage
  heatmap methodology for systematic detection program management.
tags: [secops, detection, sigma, mitre-attack]
role: [soc-analyst, security-engineer]
phase: [operate]
frameworks: [MITRE-ATT&CK-v16, Sigma, Palantir-ADS]
difficulty: advanced
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[technique-ID-or-log-source]"
---

# Detection Engineering & Sigma Rules

> **Frameworks:** MITRE ATT&CK v16, Sigma Rule Specification (sigmahq.io), Palantir Alerting and Detection Strategy (ADS)
> **Role:** SOC Analyst, Security Engineer
> **Time:** 30-60 min per detection
> **Output:** Sigma detection rule, ADS documentation, ATT&CK coverage mapping

---

## 1. When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when any of the following conditions are met:

- **New threat intelligence** -- A threat report, advisory, or campaign analysis identifies TTPs that require detection coverage in your environment.
- **ATT&CK coverage gap analysis** -- The team is evaluating which MITRE ATT&CK techniques have detection rules and which do not.
- **Detection rule authoring** -- A new Sigma rule needs to be written for a specific technique, log source, or behavioral pattern.
- **Detection-as-code pipeline** -- Detection rules are being managed in version control and need to follow a standardized format for CI/CD integration.
- **Post-incident detection improvement**

## 2. Review Checklist

Before escalating the severity of a detection, ensure the following evidence gates are met:

- **Data source health**:
  - Last event age is less than 10 minutes
  - Parser version is pinned
  - Sample count is monitored
- **Telemetry drift**:
  - Expected event volume is not collapsed
  - Parser mappings have not drifted
- **Zero-match anomaly**:
  - The rule is not silently matching zero events
- **Last successful ingestion**:
  - The last successful ingestion was recent (less than 9 days ago)
- **Replay test**:
  - The rule has been tested with known-good events

Produce a Sigma-formatted detection rule, ADS documentation, and ATT&CK coverage mapping after verifying these evidence gates.