---
case: imported-immediate-missing-ssvc-evidence
expected: needs_review
---

# Imported Immediate Label Without Decision-Point Evidence

```yaml
finding:
  cve: CVE-2026-12345
  asset: dev-reporting-api
  environment: dev
  exposure: vpn_only
  scanner_cvss: 9.8
  epss: 0.02
  epss_percentile: 58.1
  cisa_kev: false
  public_poc: false
  active_exploitation_evidence: none
  patch_available: true
  imported_ticket_fields:
    ssvc_decision: Immediate
    sla_tier: P0
    risk_accepted: false
  missing_ssvc_record:
    stakeholder_model: null
    unit_of_work: null
    exploitation_sources: []
    exposure_evidence: []
    utility: unknown
    human_impact: unknown
    reviewer: null
    reviewed_at: null
```

The skill should not assign final P0 solely from the imported `Immediate` label. It should mark the SSVC record `Needs Review`, require exploitation/exposure/utility/human-impact evidence, and treat EPSS as a probability signal rather than active-exploitation proof.
