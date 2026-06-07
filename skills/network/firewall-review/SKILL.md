---
name: firewall-review
description: >
  Performs a structured firewall rule base audit against CIS Controls v8
  (Controls 4.4 and 4.5) and NIST SP 800-41 Rev 1 (Guidelines on Firewalls and
  Firewall Policy). Auto-invoked when reviewing firewall configurations, ACLs,
  or network security policies. Produces a prioritized findings report covering
  overly permissive rules, shadowed rules, logging gaps, and egress filtering
  deficiencies. Includes evidence gates for effective cloud rules, egress destination allowlists, 
  temporary-rule expiry, owner/justification, stateful-return versus outbound initiation, and route table/NAT path validation.
tags: [network, firewall, segmentation]
role: [security-engineer]
phase: [operate]
frameworks: [CIS-Controls-v8, NIST-SP-800-41-Rev1]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.1.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Firewall Rule Audit

A structured, repeatable process for auditing firewall rule bases against CIS Controls v8 (Control 4.4 -- Implement and Manage a Firewall on Servers, Control 4.5 -- Implement and Manage a Firewall on End-User Devices) and NIST SP 800-41 Rev 1 (Guidelines on Firewalls and Firewall Policy). This skill produces findings with traceable control references, severity ratings, and actionable remediation guidance.

## Evidence Gates
The following evidence gates must be evaluated during the review:
- Ephemeral egress rules
- Cloud effective rules
- Egress destination allowlists
- Temporary-rule expiry
- Owner/justification for rules
- Stateful-return versus outbound initiation
- Route table/NAT path validation

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

- Periodic firewall rule base reviews (quarterly or after major changes).
- Compliance audits requiring CIS Controls v8 or NIST SP 800-41 alignment.
- Incident response when lateral movement or exfiltration is suspected.
- Pre-deployment review of new firewall rule sets or policy changes.
- Network architecture reviews that include perimeter or internal segmentation firewalls.

## Context

Firewall rule bases accumulate technical debt rapidly. Rules added during incidents are rarely removed. Temporary permits become permanent. Shadowed rules create a false sense of coverage. NIST SP 800-41 Rev 1 Section 4.2 explicitly states that firewalls should be configured to only allow traffic that is necessary for business purposes.

## Review Steps
1. Identify all firewall rules and evaluate them against the evidence gates.
2. Verify that all rules have a valid owner/justification and are properly documented.
3. Check for shadowed rules and remove or modify them as necessary.
4. Evaluate egress filtering and ensure that it is properly configured.
5. Review logging and ensure that all relevant traffic is being logged.
6. Verify that all temporary rules have a valid expiry date and are properly removed after expiry.

## Findings Report
The findings report should include the following information:
- A list of all firewall rules, including their owner/justification and documentation.
- A list of all shadowed rules and recommendations for removal or modification.
- An evaluation of egress filtering and recommendations for improvement.
- A review of logging and recommendations for improvement.
- A list of all temporary rules, including their expiry date and recommendations for removal or modification.