---
case_id: patch-prioritization-ssvc-primacy-relative-epss-spike
skill: patch-prioritization
expected_result: SSVC-driven SLA retained
---

# SSVC Primacy For Relative EPSS Spike

This calibration case should prevent a relative-only EPSS increase from overriding a low-urgency SSVC decision.

```yaml
finding:
  cve: CVE-2099-0005
  affected_component: internal batch processor
  asset: batch-int-11
  environment: production
  internet_exposed: false
  business_criticality: low
  cisa_kev: false
  public_poc: false
  active_exploitation_evidence: false
  patch_available: true
  ssvc:
    decision: Scheduled
    exploitation: None
    exposure: Controlled
    automatable: No
    human_impact: Low
  epss:
    score_30_days_ago: 0.0004
    current_score: 0.0012
    current_percentile: low
    percentile_change: minimal
    absolute_change: 0.0008
    relative_change: 200%
    source_date: 2099-01-31
    history_status: Complete
```

## Expected Handling

- Trend: `Low Absolute Probability`
- SLA action: retain the SSVC-driven `Scheduled` SLA
- Escalation condition: require KEV, credible exploit intelligence, exposed impact, or local policy before changing the SLA tier
