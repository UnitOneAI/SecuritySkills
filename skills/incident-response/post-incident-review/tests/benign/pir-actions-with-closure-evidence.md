# Benign PIR Fixture: Actions With Closure Evidence

## Remediation Plan

| ID | Finding | Action | Owner | Priority | Deadline | Ticket | Closure Criteria |
|---|---|---|---|---|---|---|---|
| REM-001 | EDR alert was not triaged for 18 hours | Tune alert severity and update triage runbook | SOC Engineering | P1 | 2026-06-20 | SEC-1024 | Replay test fires P1 alert, creates case, and pages on-call within 5 minutes |

## Remediation Closure Evidence

| Action ID | Closure Criteria | Verification Evidence | Independent Verifier | Residual Risk Owner | Effectiveness Check | Status |
|---|---|---|---|---|---|---|
| REM-001 | Replay test fires P1 alert, creates case, and pages on-call within 5 minutes | Detection test report DET-2026-0615 and runbook PR SEC-RB-88 | Detection Lead | None | 2026-07-15 | Verified |
