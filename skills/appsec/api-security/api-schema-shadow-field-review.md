---
name: api-schema-shadow-field-review
description: >
  Detects shadow fields and undocumented schema properties in REST and GraphQL
  APIs that carry privileged meaning without receiving the same review as
  visible API parameters. Maps trust boundaries, identifies authority
  derivation, and reviews validation, provenance, exception handling,
  replay behavior, and background/operator paths.
tags: [appsec, api, rest, graphql, schema, shadow-field, authorization]
role: [appsec-engineer, security-engineer]
phase: [design, build, review]
frameworks: [OWASP-API-Security-2023, OWASP-ASVS, NIST-SP-800-53]
difficulty: intermediate
time_estimate: "30-45min"
version: "1.0.0"
author: mkcash
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# API Schema Shadow Field Review

A structured, repeatable process for detecting shadow fields and undocumented
schema properties in REST and GraphQL APIs. Shadow fields are schema
properties that carry privileged meaning (authorization signals, internal
flags, elevated permissions) but are not part of the documented API contract
and therefore bypass standard API security review processes.

---

## Intent

Prevent APIs from accepting or acting on hidden schema properties that
convey authority, permissions, or elevated access without explicit
authorization checks at the trust boundary.

---

## Why This Matters in Agentic Systems

Traditional API security reviews focus on documented endpoints and visible
parameters. Shadow fields exist in the gap between schema definitions and
implementation — properties accepted by the deserializer but absent from
OpenAPI specs, GraphQL schemas, or developer documentation. An agent
reviewing API code may miss these because they don't appear in the
surface-level contract. The blast radius: a single shadow field like
`isAdmin: true` or `bypassAuth: true` in a request body can elevate a
regular user to administrator without triggering any visible security
control.

---

## Detection Patterns

### Signal Types

| Signal | Pattern | Confidence |
|---|---|---|
| AST pattern | Deserializer binding to object with properties not in OpenAPI spec | HIGH |
| Regex | `(isAdmin|is_admin|admin|root|bypass|internal|privileged|elevated)\s*[:=]` in request DTOs | MEDIUM |
| Structural | Extra properties allowed in deserialization config (e.g., `@JsonIgnoreProperties(ignoreUnknown=false)`) | HIGH |
| Behavioral | Conditional logic branching on undocumented fields | HIGH |
| GraphQL | Input object types with fields not in schema introspection | MEDIUM |
| Structural | `additionalProperties: true` in OpenAPI schemas without explicit allowlist | MEDIUM |

### Reference Patterns

→ /references/shadow-field-patterns.md

---

## Constraints

- **MUST NOT** accept request properties that are not explicitly defined in the API contract (OpenAPI spec, GraphQL schema, or documented DTO)
- **MUST NOT** derive authorization, permissions, or elevated access from fields not present in the documented schema
- **MUST** configure deserializers to reject unknown properties by default (fail-closed)
- **MUST** implement explicit allowlists for any extensibility points (e.g., `extensions` object with defined schema)
- **MUST** log and alert on requests containing unknown/extra properties
- **MUST** verify that every property used in authorization decisions is documented and reviewed

---

## Remediation

### Fix Strategy

Replace implicit property acceptance with explicit schema validation. Configure
deserializers to reject unknown properties. Move any legitimate extensibility
into a defined `extensions` or `metadata` object with its own schema.
Implement a schema validation middleware that enforces contract conformance
before request handlers execute.

### Fix Template

→ /templates/shadow-field-remediation.md

### Automated Fix Script

→ /scripts/fix-shadow-fields.sh

### Remediation Output Example

**Before (vulnerable):**
```json
// OpenAPI spec defines only: userId, email, displayName
// But deserializer accepts: userId, email, displayName, isAdmin, internalFlags
{
  "userId": 123,
  "email": "user@example.com",
  "displayName": "John",
  "isAdmin": true,           // SHADOW FIELD - not in spec
  "internalFlags": ["bypassAuth"]  // SHADOW FIELD - not in spec
}
```

**After (remediated):**
```json
// Deserializer configured to reject unknown properties
// Request with shadow fields returns 400 Bad Request
{
  "error": "Unknown properties in request: isAdmin, internalFlags",
  "allowedProperties": ["userId", "email", "displayName"]
}
```

---

## Verification

### Expected Behavior

- All request properties are explicitly defined in the API contract
- Deserializers reject unknown properties with clear error messages
- Authorization decisions only use documented, reviewed properties
- Any extensibility mechanism has its own explicit schema
- Requests with extra properties are logged for security monitoring

### Actual Behavior Check

1. Scan all request DTOs / input types against OpenAPI spec / GraphQL schema
2. Confirm deserializer configuration rejects unknown properties (fail-closed)
3. Verify no conditional logic branches on undocumented fields
4. Check that authorization middleware only reads documented properties
5. Run the verification script at /scripts/verify-shadow-fields.sh

### Falsifiable Test

| | |
|---|---|
| **Input** | POST /api/users with body containing documented fields + `isAdmin: true` |
| **Expected output** | 400 Bad Request with "Unknown properties: isAdmin" |
| **Pass condition** | Request rejected, error mentions unknown properties, no user created with admin flag |
| **Fail condition** | Request accepted, user created with admin privileges, or silent ignore of extra fields |

### Verification Script

→ /scripts/verify-shadow-fields.sh

---

## Flexibility Guidance

- **When context changes the constraint:** Legitimate extensibility points (e.g., `metadata` object for custom integrations) must have their own explicit schema and validation. The schema should define allowed keys or use a strict map type.
- **Acceptable variation:** Versioned APIs where v2 adds fields not in v1 — each version has its own complete schema. The constraint applies per-version.
- **Escalate to human when:** Agent cannot determine whether an undocumented field is a shadow field or a legitimate but undocumented internal field (requires code review).
- **Do NOT flag:** Fields explicitly marked as `deprecated` in schema, fields in a documented `extensions`/`metadata` object with its own schema, fields in a separate `internal` namespace that is explicitly designed for internal-only clients with separate auth.

---

## Gotchas

### False Positives

- **Pattern:** Test fixtures containing extra fields for test scenarios
  **Why it fires:** Test data often includes fields not in production schema
  **How to suppress:** Detect test file paths (`**/test/**`, `**/spec/**`, `**/__tests__/**`) and downgrade severity to Informational

- **Pattern:** Documentation examples showing hypothetical future fields
  **Why it fires:** Example requests in docs may show planned fields
  **How to suppress:** Only scan implementation code (controllers, DTOs, deserializers), not markdown/docs

- **Pattern:** GraphQL `__typename` and introspection fields
  **Why it fires:** These are meta-fields added by GraphQL runtime
  **How to suppress:** Maintain allowlist of GraphQL meta-fields (`__typename`, `__schema`, `__type`)

### Precision Traps

- **Trap:** Overly strict rejection breaks legitimate API evolution
  **Scenario:** Mobile clients on old versions send fields that newer API versions don't recognize
  **Mitigation:** Version APIs explicitly. Use content negotiation or versioned paths. Never silently ignore unknown fields in current version.

- **Trap:** Deserializer configuration varies by framework
  **Scenario:** Jackson (Java), Newtonsoft/STJ (.NET), Pydantic (Python), json.Unmarshal (Go) all have different defaults
  **Mitigation:** Provide framework-specific configuration guidance in references/

### Exploit Pattern Lessons

- **Observed in:** CVE-2021-44228 (Log4Shell) - JNDI lookup via user-controlled field
  **Lesson:** Any deserialized field can become an attack vector. Fail-closed deserialization is a foundational control.

- **Observed in:** Mass assignment vulnerabilities (GitHub CVE-2022-23529, Rails strong_parameters bypass)
  **Lesson:** Framework-level protections can be bypassed. Explicit allowlist at application layer is required.

- **Observed in:** GraphQL field-level authorization bypass via alias abuse
  **Lesson:** GraphQL's flexibility allows requesting same field with different aliases. Authorization must be at resolver level, not query level.

---

## Subagent Execution Profile

| Property | Value |
|---|---|
| **Single responsibility** | YES |
| **Cross-bundle dependency** | NONE |
| **Parallelizable with** | api-security, secure-code-review, threat-modeling |
| **Estimated tokens (context load)** | MEDIUM 2–5k |
| **Recommended subagent role** | Security Scanner |

---

## File Structure

```
skills/
└── appsec/
    └── api-security/
        ├── SKILL.md                              ← category skill
        ├── api-top10-checklist.md                ← reference
        ├── csharp-dotnet.md                      ← language supplement
        ├── api-schema-shadow-field-review.md     ← THIS FILE
        ├── references/
        │   ├── shadow-field-patterns.md          ← detection pattern library
        │   └── framework-configs.md              ← per-framework deserializer configs
        ├── scripts/
        │   ├── fix-shadow-fields.sh              ← automated fix script
        │   └── verify-shadow-fields.sh           ← verification script
        └── templates/
            └── shadow-field-remediation.md       ← remediation scaffolding
```

---

## Changelog

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0.0 | 2026-06-13 | mkcash | Initial creation |

---

## Skill Sign-Off Checklist

### Authoring
- [x] Metadata YAML complete and valid
- [x] Intent is one sentence, agent-behavior-first
- [x] Why This Matters explains agentic-specific blast radius
- [x] Detection patterns include at least one machine-matchable signal (regex / AST / structural)
- [x] Constraints are hard rules — no "consider" or "may" language
- [x] Remediation links to `/scripts/` and `/templates/` (not inlined if > 15 lines)
- [x] Before/After remediation example present

### Verification
- [ ] Falsifiable test defined (binary pass/fail)
- [ ] Verification script exists at `/scripts/verify-shadow-fields.sh`
- [ ] Actual behavior check is step-by-step, not aspirational
- [ ] Verified against synthetic agent session
- [ ] Precision score set after test run

### Elegance
- [ ] No redundant sub-bullets that restate the parent
- [ ] No overlap with existing skills in the same bundle (checked against bundle index)
- [ ] Flexibility Guidance prevents over-constraining the agent
- [ ] Intent-first structure: Intent → Why → Detection → Constraints → Remediation → Verification → Flexibility → Gotchas

### System Layer
- [ ] `/references/` directory created with CVE / MITRE / pattern files
- [ ] `/scripts/` contains fix and verify scripts (or stub with TODO)
- [ ] `/templates/` contains remediation scaffolding (or stub with TODO)
- [ ] No external knowledge left inline that belongs in `/references/`

### Self-Improvement
- [ ] Gotchas section has minimum 2 false positive entries
- [ ] Gotchas section has minimum 1 precision trap entry
- [ ] Gotchas section has minimum 1 exploit pattern lesson

### Subagent Fit
- [ ] Single responsibility confirmed (no mixed concerns)
- [ ] No cross-bundle context dependency
- [ ] Parallelizable field set correctly

### Bundle Integration
- [ ] Skill added to bundle index (`/bundles/appsec/INDEX.md`)
- [ ] Skill tagged in AVE taxonomy (`/references/ave-taxonomy.md`)
- [ ] Commit message follows: `feat(skill): api-schema-shadow-field-review — shadow field detection`

---

*SecuritySkills Skill — UnitOne.ai*
*Systems > Prompts · Verification > Generation · No Lazy Fixes — Solve Root Cause*