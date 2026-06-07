name: agentic-top-10
description: >
  Reviews agentic AI systems against the OWASP Top 10 security risks for autonomous
  AI agents. Auto-invoked when reviewing multi-agent architectures, AI agent
  deployments, or systems where LLMs have tool access and act autonomously.
  Covers permission models, tool security, memory integrity, trust boundaries,
  and human oversight. Produces a structured assessment with risk ratings and
  architectural recommendations.
tags: [ai-security, agentic-ai, agents]
role: [appsec-engineer, security-engineer, architect, vciso]
phase: [design, build, review]
frameworks: [OWASP-Agentic-AI, MITRE-ATLAS, NIST-AI-RMF]
difficulty: advanced
time_estimate: "45-90min"
version: "1.0.2"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
context: fork
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# OWASP Top 10 for Agentic AI Applications — Security Review Skill

## Purpose

This skill provides a structured security assessment methodology for agentic AI systems — applications where one or more LLM-powered agents operate autonomously, invoke tools, maintain persistent memory, and collaborate with other agents or humans. It is organized around the ten threat categories identified through the OWASP GenAI Security Project's research into agentic AI risks.

This is not a theoretical exercise. Agentic AI systems are being deployed in production today for code generation, customer support, financial analysis, DevOps automation, and autonomous research. Each deployment introduces attack surface that traditional application security reviews do not cover. This skill closes that gap.

## When to Use This Skill

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when any of the following conditions are true:

- An LLM-based agent has access to tools, APIs, or system commands.
- A multi-agent architecture is under design 
- Tool outputs are used as instructions or data without proper validation and trust labeling.
- Delegated agent messages lack capability checks, original user approval, or audit logs.

## Assessment Checklist

1. **Tool Output Validation**: Verify that tool outputs are properly validated and labeled with trust indicators before being used as instructions or data.
2. **Delegated Capability Checks**: Ensure that delegated agent messages include capability checks, original user approval, and audit logs to prevent unauthorized actions.
3. **Instruction/Data Separation**: Confirm that instructions and data are properly separated to prevent tool outputs from being misinterpreted as instructions.
4. **Signed Result Envelopes**: Verify that tool results are enclosed in signed envelopes to ensure authenticity and integrity.
5. **Original User Approval Propagation**: Ensure that original user approval is propagated through delegated agent messages to prevent unauthorized actions.
6. **Audit Logs**: Confirm that audit logs are maintained to tie tool calls to the requesting agent and track the flow of instructions and data.

## Remediation Guidance

- Implement tool output validation and trust labeling to prevent malicious data from being used as instructions.
- Integrate delegated capability checks, original user approval, and audit logs into delegated agent messages to prevent unauthorized actions.
- Enforce instruction/data separation to prevent tool outputs from being misinterpreted as instructions.
- Use signed result envelopes to ensure the authenticity and integrity of tool results.
- Propagate original user approval through delegated agent messages to prevent unauthorized actions.
- Maintain audit logs to track the flow of instructions and data and tie tool calls to the requesting agent.