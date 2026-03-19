# Access Review Finding Codes Reference

> Extracted from `access-review/SKILL.md`. Use these codes when reporting access review findings.

## AR-SCOPE — Review Scope and Inventory

| Code | Finding | Framework Ref |
|---|---|---|
| AR-SCOPE-01 | No defined access review cadence | AC-2(j) |
| AR-SCOPE-02 | Review scope excludes critical systems (production databases, admin consoles) | AC-2 |
| AR-SCOPE-03 | Service accounts excluded from review population | CIS 5.5 |
| AR-SCOPE-04 | SaaS applications not included in centralized review (shadow IT gap) | CIS 6.7 |
| AR-SCOPE-05 | No single authoritative source for entitlements | CIS 6.7 |
| AR-SCOPE-06 | Guest/external accounts not included in review scope | AC-2 |

## AR-CERT — Entitlement Certification

| Code | Finding | Framework Ref |
|---|---|---|
| AR-CERT-01 | No manager/owner certification workflow exists | AC-6(7) |
| AR-CERT-02 | Rubber-stamping — certifiers approve all entitlements without review (>95% approve rate) | AC-6(7) |
| AR-CERT-03 | No evidence of review decisions (approve/revoke/modify not logged) | AC-2(4) |
| AR-CERT-04 | Certifiers lack visibility into what permissions the entitlement grants | AC-6(7) |
| AR-CERT-05 | No escalation path for entitlements where the certifier is uncertain | AC-6(7) |
| AR-CERT-06 | Certification decisions not enforced — revoked entitlements not actually removed | AC-2, CIS 6.2 |
| AR-CERT-07 | No SLA for certification completion (recommended: 14 business days) | AC-2(j) |
| AR-CERT-08 | Delegated reviews without accountability (certifier delegates but is not tracked) | AC-6(7) |

## AR-ORPH — Orphaned Account Detection

| Code | Finding | Framework Ref |
|---|---|---|
| AR-ORPH-01 | Accounts belonging to terminated employees still active | AC-2(3) |
| AR-ORPH-02 | Accounts belonging to departed contractors not deprovisioned | AC-2(3), CIS 6.2 |
| AR-ORPH-03 | Service accounts with no documented owner | CIS 5.5 |
| AR-ORPH-04 | Shared accounts with no accountable individual | AC-2 |
| AR-ORPH-05 | Accounts inactive > 45 days without documented exception | CIS 5.3 |
| AR-ORPH-06 | Accounts not correlated with authoritative HR source (HRIS feed gap) | AC-2 |
| AR-ORPH-07 | Deprovisioning SLA exceeded (same-day for terminations, 24 hours for role changes) | CIS 6.2 |
| AR-ORPH-08 | Test/temporary accounts promoted to production without lifecycle management | AC-2 |

## AR-ROLE — Role Explosion Detection

| Code | Finding | Framework Ref |
|---|---|---|
| AR-ROLE-01 | Role count exceeds user count (ratio > 1:1 indicates explosion) | CIS 6.8 |
| AR-ROLE-02 | Roles with single-user assignment (likely snowflake roles) | CIS 6.8 |
| AR-ROLE-03 | Roles with overlapping permissions (> 80% permission overlap between roles) | CIS 6.8 |
| AR-ROLE-04 | Roles not reviewed or updated in > 12 months | AC-2(j) |
| AR-ROLE-05 | No role lifecycle process (creation, modification, retirement) | CIS 6.8 |
| AR-ROLE-06 | Role naming conventions inconsistent or undocumented | CIS 6.8 |
| AR-ROLE-07 | Nested role hierarchies exceeding 3 levels (complexity creates audit blind spots) | CIS 6.8 |
| AR-ROLE-08 | Custom roles duplicating built-in/managed role permissions | CIS 6.8 |

## AR-SOD — Segregation of Duties

| Code | Finding | Framework Ref |
|---|---|---|
| AR-SOD-01 | No documented SoD matrix or conflict rules | AC-5 |
| AR-SOD-02 | SoD violations detected — user holds both sides of a conflict pair | AC-5 |
| AR-SOD-03 | SoD violations with no compensating controls documented | AC-5 |
| AR-SOD-04 | SoD analysis not automated (manual review only) | AC-5 |
| AR-SOD-05 | Emergency/break-glass access bypasses SoD without post-hoc review | AC-5 |
| AR-SOD-06 | Role combinations that create SoD conflicts not flagged during provisioning | AC-5 |
| AR-SOD-07 | SoD conflicts in service accounts (single account spans multiple functions) | AC-5 |

## AR-ENF — Remediation Enforcement

| Code | Finding | Framework Ref |
|---|---|---|
| AR-ENF-01 | Revocation decisions from reviews not executed within SLA | AC-2, CIS 6.2 |
| AR-ENF-02 | No automated enforcement — revocations require manual ticket processing | AC-2(1) |
| AR-ENF-03 | Review evidence (decisions, timestamps, certifier identity) not retained | AC-2(4) |
| AR-ENF-04 | Evidence retention period less than audit window (SOC 2 requires 12 months) | AC-2 |
| AR-ENF-05 | No reconciliation between review decisions and actual access state | AC-6(7) |
| AR-ENF-06 | Exception process not documented or exceptions not time-bounded | AC-6 |
| AR-ENF-07 | Compensating controls for exceptions not validated | AC-6 |
| AR-ENF-08 | No metrics or reporting on review completion rates and outcomes | AC-2(j) |
