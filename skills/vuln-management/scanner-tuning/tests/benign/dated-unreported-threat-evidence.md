---
case_id: scanner-tuning-dated-unreported-threat-evidence
skill: scanner-tuning
expected_result: CVSS-BT monitored without active-exploitation escalation
---

# Dated Unreported Threat Evidence

This calibration case should confirm that `E:U` evidence is recorded and dated without inventing active exploitation.

```yaml
finding:
  scanner: Tenable
  plugin_id: "nessus-2099007"
  cve: CVE-2099-0077
  asset: internal-reporting-12
  original_severity: High
  original_score:
    label: CVSS-B
    vector_source: CNA advisory
    vector_source_date: 2099-01-12
    vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
  threat_metric:
    exploit_maturity: E:U
    source_type: vendor advisory plus exploit repository review
    source_url: https://example.invalid/vendor/security/CVE-2099-0077
    observation_date: 2099-01-31
    confidence: Medium
  supplemental_context:
    automatable: No
    recovery: Automatic
    value_density: Diffuse
    provider_urgency: Clear
  environmental_context:
    internet_exposed: false
    data_classification: internal
    compensating_controls:
      - authenticated-only service
      - no externally reachable path
```

## Expected Handling

- Selected score label: `CVSS-BT`
- Threat evidence: record `E:U`, source type, source URL or artifact, observation date, and confidence
- Escalation: do not classify as active exploitation unless stronger dated evidence appears
- Review note: stale `E:U` evidence should be rechecked before quarterly override renewal
