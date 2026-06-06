# Scan-Window Coverage Fixtures

These fixtures calibrate the maintenance-blackout and stale scan-window coverage
gates in `scanner-tuning`. They are not executable tests. Use them as review
scenarios when deciding whether a scan policy is genuinely tuned or merely
deferential to operations.

## Fixture Format

Each fixture records:

- `source`: the scan policy, result summary, or remediation evidence being reviewed.
- `coverage_path`: how the policy claims coverage despite timing constraints.
- `evidence`: proof required before accepting the policy as tuned.
- `expected_decision`: the expected tuning outcome.
- `evidence_gate`: the output value to use in the report.

## Fixtures

```yaml
id: blackout-with-catch-up-and-emergency-path
source: Production vulnerability scan policy for payment services.
coverage_path: Scans pause during quarter-end change freeze.
evidence:
  - Catch-up credentialed scan runs within 24 hours after blackout ends.
  - KEV and internet-facing critical CVEs can trigger targeted scans during blackout.
  - Missed-host report is reviewed by asset owner and vulnerability manager.
  - Agent-based package inventory continues during the freeze.
expected_decision: tuned_with_blackout_compensation
evidence_gate: Blackout compensation verified
```

```yaml
id: quarter-end-freeze-creates-stale-coverage
source: PROD-WINDOW-ONLY policy for finance and ERP assets.
coverage_path: No scans during the last ten days of every quarter.
evidence:
  - No make-up scan or risk acceptance exists for skipped weeks.
  - Critical hosts last completed authenticated scan 46 days ago.
  - Patch SLA closure uses the previous scan result, not post-remediation validation.
  - Missed-host list is not tracked by asset tier or business service.
expected_decision: finding_expected
evidence_gate: Stale blackout coverage
minimum_classification: Basic
```

```yaml
id: short-window-misses-high-risk-hosts
source: Sunday 02:00-06:00 authenticated scan schedule.
coverage_path: Policy marks scope as weekly credentialed coverage.
evidence:
  - Scan reports show 72% completion before the maintenance window closes.
  - Skipped hosts are mostly production databases and internet-facing jump hosts.
  - Credential success rate is high for completed hosts but unmeasured for skipped hosts.
  - No staggered window or agent fallback exists for the missed asset groups.
expected_decision: finding_expected
evidence_gate: Scan-window completion gap
minimum_classification: Basic
```

```yaml
id: patch-validation-after-remediation
source: Critical OpenSSL remediation campaign for internet-facing services.
coverage_path: Targeted rescan validates patched assets before SLA closure.
evidence:
  - Remediation ticket links each asset to a post-patch authenticated scan.
  - The scan ran after package upgrade and service restart.
  - Internet-facing DNS and load-balancer pools match the rescanned scope.
  - Remaining failures have owner, due date, and compensating control evidence.
expected_decision: optimized_with_post_patch_validation
evidence_gate: Patch validation timing verified
```

```yaml
id: emergency-cve-waits-for-routine-window
source: New CISA KEV-listed RCE affects public VPN appliances.
coverage_path: Scanner policy waits for the next weekly full scan.
evidence:
  - No same-day targeted scan workflow exists for KEV or ransomware-used CVEs.
  - External perimeter scan is weekly and last ran before the advisory.
  - Asset inventory has public VPN endpoints but no confirmed version data.
  - Risk acceptance is absent for delaying validation.
expected_decision: finding_expected
evidence_gate: Emergency CVE path missing
minimum_classification: Poorly Tuned
```
