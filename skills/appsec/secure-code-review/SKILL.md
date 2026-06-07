---
name: secure-code-review
description: >
  Performs a structured security code review against OWASP ASVS 4.0.3 verification
  requirements and CWE Top 25. Auto-invoked on pull request reviews, when code
  touching authentication, authorization, cryptography, or input handling is shared.
  Produces findings mapped to ASVS controls and CWE identifiers with severity
  ratings and specific remediation guidance.
tags: [appsec, code-review, sast]
role: [appsec-engineer, security-engineer]
phase: [build, review]
frameworks: [OWASP-ASVS, CWE-Top-25, OWASP-Top-10]
difficulty: intermediate
time_estimate: "15-45min per module"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Secure Code Review

A structured, repeatable process for performing security-focused code review grounded in OWASP Application Security Verification Standard (ASVS) 4.0.3 and the CWE Top 25 Most Dangerous Software Weaknesses (2024 edition). This skill produces findings with traceable control IDs, severity ratings, and actionable remediation guidance.

## Step 1: Scope and Language Identification

If a target is provided via arguments, focus the review on: $ARGUMENTS

Before examining any code, establish the review boundary.

1. **Identify the languages and frameworks** present in the changeset (Python, JavaScript/TypeScript, Go, Java, etc.).
2. **Catalog the modules under review** -- list every file path and its primary responsibility (route handler, data model, utility, middleware, configuration).
3. **Determine trust boundaries** -- mark where user-controlled data enters the system (HTTP parameters, headers, file uploads, message queues, environment variables).
4. **Note dependencies** -- third-party libraries that handle security-sensitive operations (auth libraries, ORM layers, crypto packages, templating engines).
5. **Map ASVS sections** to the codebase, focusing on input validation, authentication, authorization, data protection, and error handling.

## Step 2: Template Injection and Context Escaping Review

1. **Identify template engines** in use (Jinja, Twig, Django, Handlebars, Liquid, ERB).
2. **Check for user-controlled template sources**:
   - Look for templates loaded from user input or external sources.
   - Verify that template sources are properly sanitized and validated.
3. **Verify sandbox mode**:
   - Check if the template engine is running in sandbox mode.
   - Ensure that sandbox mode is properly configured to restrict access to sensitive data and functions.
4. **Inspect for dangerous globals**:
   - Check for the presence of dangerous globals that could be used to bypass security controls.
   - Verify that these globals are properly restricted or removed.
5. **Check autoescape status**:
   - Verify that autoescaping is enabled for HTML contexts.
   - Check for any instances where autoescaping is disabled or bypassed.
6. **Verify output context**:
   - Check the output context of template rendering (HTML body, attribute, URL, JS string, email HTML).
   - Ensure that the output context is properly handled to prevent XSS attacks.

## Step 3: Evidence Gates and Compensating Controls

1. **Check for evidence of template injection protection**:
   - Look for code that sanitizes or validates user input used in template rendering.
   - Verify that template engines are properly configured to prevent template injection attacks.
2. **Verify compensating controls**:
   - Check for additional security controls that mitigate the risk of template injection attacks (e.g., input validation, output encoding).
   - Ensure that these controls are properly implemented and effective.

## Step 4: Reporting and Remediation

1. **Document findings**:
   - Record all identified vulnerabilities and weaknesses.
   - Provide recommendations for remediation and mitigation.
2. **Prioritize and rate findings**:
   - Assign a severity rating to each finding based on the potential impact and likelihood of exploitation.
   - Prioritize findings for remediation based on severity and business risk.
3. **Provide remediation guidance**:
   - Offer specific, actionable recommendations for remediating identified vulnerabilities and weaknesses.
   - Include examples of secure coding practices and code snippets to illustrate remediation steps.