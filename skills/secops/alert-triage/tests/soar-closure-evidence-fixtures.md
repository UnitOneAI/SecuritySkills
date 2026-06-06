# SOAR Closure Evidence Fixtures

These fixtures calibrate the SOAR auto-disposition and closure-integrity gates
in `alert-triage`. They are not executable tests. Use them as review scenarios
when deciding whether a closure can support FP/BTP disposition, should remain
Not Evaluable, or requires escalation.

## Fixture Format

Each fixture records:

- `source`: the alert, case, or automation record being reviewed.
- `closure_path`: how the disposition or closure was created.
- `evidence`: proof required before trusting the disposition.
- `expected_decision`: the expected triage outcome.
- `evidence_gate`: the output value to use in the report.

## Fixtures

```yaml
id: soar-validated-maintenance-btp
source: Endpoint alert for signed admin PowerShell on patch-window servers.
closure_path: SOAR playbook proposed BTP; named analyst approved the closure.
evidence:
  - Case history shows analyst approval after reviewing EDR process tree.
  - Maintenance ticket matches host group, user, time window, and command hash.
  - Playbook version and allowlist entry are recorded with expiry.
  - No linked alerts show lateral movement, credential access, or exfiltration.
expected_decision: benign_true_positive_with_evidence
evidence_gate: Analyst validated closure
```

```yaml
id: soar-auto-fp-without-validation
source: SIEM alert for suspicious PowerShell encoded command on finance host.
closure_path: SOAR auto-closed as false positive using a low-severity branch.
evidence:
  - closed_by is a generic automation account with no accountable owner.
  - Closure note says "known benign" without raw-event or correlation evidence.
  - No analyst review, EDR process tree, user context, or threat-intel result is attached.
  - The affected asset is production finance infrastructure.
expected_decision: not_evaluable_or_escalate
evidence_gate: Automation closure not validated
minimum_priority: P3
```

```yaml
id: duplicate-parent-contaminates-child-alerts
source: Parent incident and five child alerts across different hosts and users.
closure_path: Ticketing workflow closed every child case when the parent was marked duplicate.
evidence:
  - Parent duplicate reason references only one workstation and one user.
  - Child alerts include separate hosts, service accounts, and ATT&CK tactics.
  - No per-child evidence records explain why each alert shares the same root cause.
  - Closure propagation also stopped notifications for future child alerts in the group.
expected_decision: finding_expected
evidence_gate: Contaminated linked-case closure
minimum_priority: P2
```

```yaml
id: narrowly-scoped-soar-suppression
source: Recurrent EDR alert from approved vulnerability scanner activity.
closure_path: SOAR closes matching cases and opens a detection-tuning request.
evidence:
  - Scanner service account, source subnet, destination scope, and scan window are fixed.
  - Tuning request has owner approval, expiry, and detection-engineering review.
  - Alerts outside the scanner subnet, window, or command signature remain open.
  - Monthly review compares suppressed volume with raw telemetry samples.
expected_decision: benign_with_tuning_review
evidence_gate: Scoped automation closure
```

```yaml
id: soar-status-overrides-malicious-indicators
source: Cloud alert for impossible travel followed by mailbox export.
closure_path: UEBA enrichment marks user low risk and SOAR lowers priority to P4.
evidence:
  - Risk score is stale and was calculated before the mailbox export event.
  - Linked OAuth consent, inbox rule creation, and export audit events are present.
  - No analyst validated the enrichment order or user-session timeline.
  - Automation used absence of malware indicators as a closure criterion.
expected_decision: escalate_true_positive_review
evidence_gate: Automation contradicted by correlated evidence
minimum_priority: P2
```
