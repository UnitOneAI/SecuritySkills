# Deferred Vulnerability Revalidation Gates

Use these cases to validate that `patch-prioritization` does not treat active risk exceptions as valid after the assumptions behind the exception change.

## Case 1: Patch-unavailable exception after vendor fix

**Input**

```yaml
exception:
  id: EXC-2026-101
  cve: CVE-2026-12345
  status: approved
  reason: vendor patch unavailable
  original_sla: P2
  review_date: "2026-09-01"
current_state:
  vendor_patch: released
  vendor_advisory_date: "2026-06-15"
  cisa_kev: false
  epss_current: 0.18
  asset_exposure: internal
```

**Expected result**

The exception is no longer valid as-is. The report must set a patch-available deadline, schedule a patch window, and record a human-approved action if risk is still accepted.

## Case 2: KEV listing plus EPSS surge

**Input**

```yaml
exception:
  id: EXC-2026-102
  cve: CVE-2026-23456
  status: approved
  original_sla: P3
  compensating_control: waf_rule
current_state:
  cisa_kev: true
  bod_due_date: "2026-07-01"
  epss_current: 0.73
  epss_30_day_prior: 0.08
  public_exploit: reliable_poc
  asset_exposure: internet_facing
```

**Expected result**

The vulnerability must be re-triaged immediately. KEV, EPSS surge, reliable PoC, and internet exposure require SSVC/SLA re-evaluation and P0/P1 owner visibility rather than waiting for the review date.

## Case 3: Exposure drift invalidates acceptance

**Input**

```yaml
exception:
  id: EXC-2026-103
  cve: CVE-2026-34567
  status: approved
  reason: asset internal only
  original_sla: P3
current_state:
  asset_exposure_previous: internal
  asset_exposure_current: internet_facing
  business_criticality_current: critical
  cmdb_change_date: "2026-06-20"
```

**Expected result**

The prior acceptance assumptions are stale. Re-score asset exposure and business criticality, shorten the deadline if needed, and record the resulting action in the Deferred Vulnerability Revalidation table.

## Case 4: Compensating control no longer works

**Input**

```yaml
exception:
  id: EXC-2026-104
  cve: CVE-2026-45678
  status: approved
  original_sla: P2
  compensating_control: waf_virtual_patch
current_state:
  new_exploit_path: bypasses_original_waf_signature
  control_retest: failed
  affected_assets_covered: 12_of_20
  residual_risk: undocumented
```

**Expected result**

Remove the SLA extension or mark it invalid until the control is updated and retested. The report must not classify posture as healthy while the exception depends on a failed or stale control.

## Case 5: No material trigger, but evidence required

**Input**

```yaml
exception:
  id: EXC-2026-105
  cve: CVE-2026-56789
  status: approved
  original_sla: P4
  review_date: "2026-07-30"
current_state:
  vendor_patch: unavailable
  cisa_kev: false
  bod_due_date: null
  epss_current: 0.012
  epss_30_day_prior: 0.011
  public_exploit: none
  asset_exposure: internal
  compensating_control_validation: passed
```

**Expected result**

Maintaining the exception is acceptable only if the report records last revalidation date, triggers checked, current evidence source, resulting action, human approver when required, and next revalidation date.

## Case 6: Source feed unavailable

**Input**

```yaml
exception:
  id: EXC-2026-106
  cve: CVE-2026-67890
  status: approved
  original_sla: P2
  review_date: "2026-08-15"
current_state:
  vendor_advisory_feed:
    status: unavailable
    last_successful_check: "2026-05-01"
  cisa_kev_feed:
    status: timeout
    last_successful_check: "2026-05-01"
  epss_feed:
    status: stale
    last_successful_check: "2026-05-01"
  scanner_run:
    status: failed_authentication
    last_successful_check: "2026-04-29"
```

**Expected result**

The exception must be marked Not Evaluable rather than maintained as healthy. The report should route the record to human review, refresh source evidence, and avoid extending the deferral until KEV, EPSS, vendor advisory, and scanner evidence are current.

## Case 7: KEV with mandatory due date

**Input**

```yaml
exception:
  id: EXC-2026-107
  cve: CVE-2026-78901
  status: approved
  original_sla: P3
  new_deadline: "2026-09-30"
current_state:
  cisa_kev: true
  bod_due_date: "2026-07-10"
  public_exploit: weaponized
  active_exploitation: observed
  asset_exposure: internet_facing
  compensating_control_validation: not_tested_after_kev
```

**Expected result**

The exception cannot keep the later September deadline. The report must record the mandatory due date, re-run SSVC, escalate the SLA, retest controls against the current exploit path, and revoke or shorten the exception unless a current human approval accepts the updated risk.
