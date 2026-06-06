---
case_id: patch-prioritization-insufficient-epss-history-first-seen
skill: patch-prioritization
expected_result: Insufficient History
---

# Insufficient EPSS History For First-Seen CVE

This calibration case should prevent missing or zero historical EPSS values from being converted into an undefined or infinite relative surge.

```yaml
finding:
  cve: CVE-2099-0003
  affected_component: customer-facing API dependency
  asset: api-prod-17
  environment: production
  internet_exposed: true
  business_criticality: medium
  cisa_kev: false
  public_poc: false
  active_exploitation_evidence: false
  patch_available: true
  ssvc_decision: Scheduled
  epss:
    score_30_days_ago: 0
    current_score: 0.003
    current_percentile: low
    absolute_change: 0.003
    relative_change: undefined_or_infinite
    source_date: 2099-01-31
    history_status: First Seen
```

## Expected Handling

- Trend: `Insufficient History`
- SLA action: keep the SSVC-driven SLA while collecting fresh EPSS history
- Escalation condition: only KEV, credible exploit intelligence, exposed high-impact context, or local policy should override the missing-history guardrail
