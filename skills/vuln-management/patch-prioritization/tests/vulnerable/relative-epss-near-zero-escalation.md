---
case_id: patch-prioritization-relative-epss-near-zero-escalation
skill: patch-prioritization
expected_result: Low Absolute Probability
---

# Relative EPSS Near-Zero Escalation

This calibration case should prevent a relative-only EPSS increase from being treated as an emergency patch trigger.

```yaml
finding:
  cve: CVE-2099-0001
  affected_component: internal package mirror
  asset: dev-mirror-02
  environment: development
  internet_exposed: false
  business_criticality: low
  cisa_kev: false
  public_poc: false
  active_exploitation_evidence: false
  patch_available: true
  ssvc_decision: Scheduled
  epss:
    score_30_days_ago: 0.0005
    current_score: 0.0016
    current_percentile: low
    absolute_change: 0.0011
    relative_change: 220%
    source_date: 2099-01-31
    history_status: Complete
```

## Expected Handling

- Trend: `Low Absolute Probability`
- SLA action: keep the SSVC-driven `Scheduled` SLA unless stronger exploit, exposure, KEV, or human-impact evidence exists
- Report note: relative EPSS change is high, but current probability and absolute delta remain below escalation floors
