---
case_id: patch-prioritization-low-baseline-epss-monitor
skill: patch-prioritization
expected_result: Low Absolute Probability
---

# Low Baseline EPSS Monitor

This calibration case should keep a low-probability, internal-only vulnerability out of urgent trend alerts even when relative growth is noticeable.

```yaml
finding:
  cve: CVE-2099-0004
  affected_component: internal reporting library
  asset: reporting-dev-04
  environment: development
  internet_exposed: false
  business_criticality: low
  cisa_kev: false
  public_poc: false
  active_exploitation_evidence: false
  patch_available: true
  ssvc_decision: Scheduled
  epss:
    score_30_days_ago: 0.0008
    current_score: 0.0022
    current_percentile: low
    percentile_change: minimal
    absolute_change: 0.0014
    relative_change: 175%
    source_date: 2099-01-31
    history_status: Complete
```

## Expected Handling

- Trend: `Low Absolute Probability`
- SLA action: monitor and retain the SSVC-driven schedule
- Report note: probability and percentile movement do not support out-of-cycle remediation
