---
case: asset-scoped-ssvc-record-with-mitigation
expected: scheduled_with_verified_mitigation
---

# Asset-Scoped SSVC Record With Verified Mitigation

```yaml
finding:
  cve: CVE-2026-22222
  asset: payments-admin-ui
  environment: production
  patch_available: true
  next_standard_window: 2026-06-18
  ssvc_record:
    stakeholder_model: deployer
    unit_of_work: "CVE-2026-22222 + payments-admin-ui + vendor patch"
    exploitation:
      value: public_poc
      sources:
        - type: vendor_advisory
          url: redacted-vendor-advisory
          checked_at: 2026-06-05
    system_exposure:
      value: controlled
      evidence: "admin UI behind VPN, MFA, and IP allowlist; external scan blocked"
    utility:
      automatable: no
      value_density: concentrated
    human_impact:
      mission_impact: degraded
      safety_impact: negligible
    decision:
      value: scheduled
      derived_from: local_tree
      reviewer: vuln-management-lead
      reviewed_at: 2026-06-05
      confidence: high
  mitigation_recheck:
    pre_mitigation_decision: out_of_cycle
    mitigation: "WAF rule and IP allowlist validated against PoC request path"
    verification: "attack-path test passed on 2026-06-05"
    post_mitigation_exposure: controlled
    post_mitigation_decision: scheduled
```

The skill should accept the scheduled tier because the decision is asset-scoped, sourced, reviewed, and tied to verified mitigation evidence. The report should still preserve the pre-mitigation decision and the changed decision points.
