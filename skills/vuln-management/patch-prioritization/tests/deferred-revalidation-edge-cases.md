# Deferred Vulnerability Revalidation Edge Cases

Use these cases to validate that `patch-prioritization` revalidates deferred vulnerabilities and risk exceptions when the original assumptions change.

## Case 1: Vendor patch released after "patch unavailable" exception

**Input**

```yaml
exception:
  id: EXC-2026-0042
  cve: CVE-2026-12345
  status: approved
  reason: vendor patch unavailable
  original_sla: P2
  review_date: 2026-09-01
current_state:
  vendor_patch: released
  vendor_advisory_date: 2026-06-15
  epss: 0.18
  cisa_kev: false
  asset_exposure: internal
```

**Expected result**

The exception must be revalidated immediately. "Patch unavailable" is no longer a valid basis, and the report must set a new remediation deadline and patch window instead of leaving the exception unchanged until September.

## Case 2: KEV listing and EPSS surge during approved exception

**Input**

```yaml
exception:
  id: EXC-2026-0051
  cve: CVE-2026-23456
  status: approved
  original_sla: P3
  compensating_control: waf_rule
  review_date: 2026-08-30
current_state:
  cisa_kev: true
  epss_current: 0.73
  epss_30_day_prior: 0.08
  public_exploit: reliable_poc
  asset_exposure: internet_facing
```

**Expected result**

Escalate immediately. KEV listing, EPSS surge, reliable public exploit, and internet exposure invalidate routine review cadence and require SSVC/SLA re-evaluation with P0/P1 leadership visibility.

## Case 3: Asset exposure drift invalidates risk acceptance

**Input**

```yaml
exception:
  id: EXC-2026-0060
  cve: CVE-2026-34567
  status: approved
  reason: asset internal only
  original_sla: P3
current_state:
  asset_exposure_previous: internal
  asset_exposure_current: internet_facing
  business_criticality_current: critical
  cmdb_change_date: 2026-06-20
  compensating_control_validation: stale
```

**Expected result**

Re-score the vulnerability using the current exposure and criticality. The previous risk acceptance must not remain valid because it depended on obsolete asset assumptions.

## Case 4: Compensating control fails after exploit details change

**Input**

```yaml
exception:
  id: EXC-2026-0077
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

Remove the SLA extension or mark it invalid. The report must require updated control testing, residual risk documentation, and a new remediation deadline for uncovered or bypassable assets.

## Case 5: No material change with documented revalidation

**Input**

```yaml
exception:
  id: EXC-2026-0088
  cve: CVE-2026-56789
  status: approved
  original_sla: P3
  review_date: 2026-07-30
current_state:
  vendor_patch: unavailable
  cisa_kev: false
  epss_current: 0.012
  epss_30_day_prior: 0.011
  public_exploit: none
  asset_exposure: internal
  compensating_control_validation: passed
```

**Expected result**

Maintain the exception only if the report records the last revalidation date, trigger checks, current finding, owner, and next revalidation date.
