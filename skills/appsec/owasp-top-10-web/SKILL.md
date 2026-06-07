---
name: owasp-top-10-web
description: >
  Reviews web applications against the OWASP Top 10:2021 vulnerability categories.
  Auto-invoked when reviewing web application code, server configurations, or
  when a user asks for a general security review of a web application. Produces
  structured findings mapped to A01-A10 with CWE references, severity ratings,
  and specific remediation guidance.
tags: [appsec, web, owasp]
role: [appsec-engineer, security-engineer]
phase: [build, review]
frameworks: [OWASP-Top-10-2021]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.2"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# OWASP Top 10:2021 — Web Application Security Review

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when:

- Reviewing web application source code for security vulnerabilities.
- Auditing server or framework configurations (e.g., Express, Django, Rails, Spring Boot, ASP.NET).
- A user requests a "security review," "pentest prep," or "OWASP check" against a web application.
- Evaluating pull requests that touch authentication, authorization, input handling, cryptography, or external integrations.
- Assessing a new web project's architecture for secure design principles before implementation begins.

Do **not** use this skill for mobile-only, IoT firmware, or non-web API reviews — use a domain-specific skill instead.

## Context

The OWASP Top 10:2021 is the authoritative awareness document for web application security. It represents broad consensus on the most critical security risks to web applications, derived from CWE data mapped across hundreds of organizations. Each category aggregates multiple CWEs under a unifying risk theme.

This skill operationalizes all ten categories into a repeatable, structured review process suitable for AI-assisted code reviews. It includes evidence fields for:

* Cookie attributes (e.g., Secure, HttpOnly, SameSite)
* Token storage location (e.g., localStorage, sessionStorage, cookies)
* Rotation and revocation of tokens and cookies
* CSRF binding and protection
* Session fixation testing and prevention

## Review Checklist

The following checklist items are used to evaluate the security of a web application:

1. **A01:2021 - Broken Access Control**: Verify that access controls are properly implemented and enforced.
2. **A02:2021 - Cryptographic Failures**: Ensure that cryptographic mechanisms are properly used and configured.
3. **A03:2021 - Injection**: Verify that user input is properly sanitized and validated to prevent injection attacks.
4. **A04:2021 - Insecure Design**: Evaluate the design of the web application for security flaws and weaknesses.
5. **A05:2021 - Security Misconfiguration**: Verify that the web application is properly configured and secured.
6. **A06:2021 - Vulnerable and Outdated Components**: Ensure that all components and dependencies are up-to-date and secure.
7. **A07:2021 - Identification and Authentication Failures**: Verify that identification and authentication mechanisms are properly implemented and secured.
8. **A08:2021 - Software and Data Integrity Failures**: Ensure that software and data integrity are properly maintained and secured.
9. **A09:2021 - Security Logging and Monitoring Failures**: Verify that security logging and monitoring are properly implemented and configured.
10. **A10:2021 - Server-Side Request Forgery (SSRF)**: Ensure that SSRF attacks are properly prevented and mitigated.

## Evidence Fields

The following evidence fields are used to collect and evaluate evidence during the review process:

* `cookie_attributes`: Verify that cookies are properly configured with attributes such as Secure, HttpOnly, and SameSite.
* `token_storage_location`: Evaluate the storage location of tokens, such as localStorage, sessionStorage, or cookies.
* `token_rotation`: Verify that tokens are properly rotated and revoked.
* `csrf_binding`: Ensure that CSRF protection is properly implemented and enforced.
* `session_fixation_testing`: Verify that session fixation testing and prevention are properly implemented.

## Remediation Guidance

Remediation guidance is provided for each checklist item and evidence field to help address identified security vulnerabilities and weaknesses.