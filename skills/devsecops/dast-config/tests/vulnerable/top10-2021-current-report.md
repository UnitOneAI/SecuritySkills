# Vulnerable Fixture: Stale Top 10:2021 DAST Report

## DAST Configuration Assessment Report

### Scope

- Target application: example app
- DAST tool(s): ZAP
- Configuration files analyzed: `af-plan.yaml`
- Date: 2026-06-03
- Frameworks applied: OWASP Top 10:2021, OWASP Testing Guide v4.2

### OWASP Top 10 DAST Coverage

| OWASP Category | Scan Rules Active | Passive | Active | Gap |
|---------------|-------------------|---------|--------|-----|
| A03 Injection | 8 | No | Yes | None |
| A06 Vulnerable Components | 1 | Yes | No | None |
| A10 SSRF | 1 | No | Yes | None |

### Expected Skill Behavior

Flag this report because it emits OWASP Top 10:2021 as current, treats runtime component fingerprinting as complete supply-chain coverage, and has no A10:2025 exceptional-condition test evidence.

