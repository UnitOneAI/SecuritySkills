name: threat-modeling
description: >
  Runs a structured STRIDE threat model on any system design, API specification,
  or codebase. Auto-invoked when the user discusses architecture, shares a system
  diagram or design document, or asks "what could go wrong?" Produces threat actor
  profiles, component-threat matrix, a threat register with STRIDE classification,
  data-flow diagram template, trust boundary identification, and prioritized
  mitigations mapped to MITRE ATT&CK techniques.
tags: [appsec, design, architecture, threat-model]
role: [security-engineer, architect, appsec-engineer, vciso]
phase: [design, review]
frameworks: [STRIDE, PASTA, MITRE-ATT&CK]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
context: fork
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Threat Modeling Skill — STRIDE Methodology

## 1. When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill whenever any of the following conditions are met:

- **New service or microservice design** — A new component is being introduced into the architecture and needs threat analysis before implementation begins.
- **Architecture review** — An existing system is undergoing redesign, migration, or significant refactoring (e.g., monolith-to-microservices, on-prem-to-cloud).
- **PRD with infrastructure implications** — A product requirements document describes features that involve new data stores, external integrations, authentication changes, or network topology modifications.
- **API design** — New or modified API endpoints are being defined, especially those that accept user input, handle authentication tokens, or expose sensitive data.
- **Pre-launch security review** — A system is approaching production deployment and requires a structured assessment of threats before go-live.
- **Compliance review** — A system is undergoing a compliance review and requires a threat model to identify potential security risks.

## 2. Threat Modeling Process

The threat modeling process involves the following steps:

1. **Identify the system's components and data flows** — Create a data-flow diagram (DFD) to visualize the system's components, data flows, and trust boundaries.
2. **Identify potential threats** — Use the STRIDE methodology to identify potential threats to the system, including:
	* **Spoofing** — Threats that involve impersonating a legitimate user or system.
	* **Tampering** — Threats that involve modifying or manipulating data.
	* **Repudiation** — Threats that involve denying or disputing a transaction or action.
	* **Information disclosure** — Threats that involve exposing sensitive data.
	* **Denial of service** — Threats that involve disrupting or denying access to the system.
	* **Elevation of privilege** — Threats that involve gaining unauthorized access or privileges.
3. **Assess the likelihood and impact of each threat** — Evaluate the likelihood and potential impact of each identified threat.
4. **Prioritize and mitigate threats** — Prioritize the threats based on their likelihood and potential impact, and implement mitigations to reduce the risk.

## 3. Asynchronous Flow Considerations

When modeling asynchronous flows, consider the following:

* **Replay attacks** — Threats that involve replaying a valid message or event to exploit a vulnerability.
* **Dead-letter queue (DLQ) abuse** — Threats that involve exploiting DLQ messages to gain unauthorized access or privileges.
* **Message age and idempotency** — Consider the age of messages and the use of idempotency keys to prevent replay attacks.
* **Producer identity and consumer authorization** — Verify the identity of producers and consumers, and ensure that consumers are authorized to process messages.
* **DLQ replay approval and original-context preservation** — Ensure that DLQ messages are properly approved and that the original context is preserved during replay.

## 4. Example Threat Model

The following is an example threat model for an e-commerce system:

| Threat | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| Spoofing | An attacker impersonates a legitimate user. | Medium | High | Implement authentication and authorization mechanisms. |
| Tampering | An attacker modifies or manipulates data. | Low | Medium | Implement data encryption and access controls. |
| Repudiation | An attacker denies or disputes a transaction. | Medium | High | Implement auditing and logging mechanisms. |
| Information disclosure | An attacker exposes sensitive data. | High | Critical | Implement data encryption and access controls. |
| Denial of service | An attacker disrupts or denies access to the system. | Medium | High | Implement load balancing and redundancy mechanisms. |
| Elevation of privilege | An attacker gains unauthorized access or privileges. | Low | Medium | Implement role-based access control and auditing mechanisms. |

By following this threat modeling process and considering asynchronous flow considerations, you can identify and mitigate potential security risks in your system.