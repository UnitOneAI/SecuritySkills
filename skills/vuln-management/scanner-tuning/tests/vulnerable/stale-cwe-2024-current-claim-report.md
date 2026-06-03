# Scanner Tuning Report Fixture: Stale CWE Evidence Presented as Current

## Scanner Tuning Report
**Date:** 2026-06-03
**Skill:** scanner-tuning v1.0.0
**Frameworks:** CVSS 4.0, CWE
**Reviewer:** AI-assisted (human review required for policy changes and severity overrides)

### Evidence Sources

| Evidence Source | Version or Date | Purpose | Status |
|---|---|---|---|
| CWE taxonomy | Not stated | Cross-scanner weakness classification | Missing |
| CWE Top 25 | 2024 list only | Advisory prioritization by weakness prevalence and impact | Current |
| CWE Top 10 KEV Weaknesses | Not checked | Advisory prioritization for exploited weakness patterns | Not performed |
| NVD CVSS | Not stated | CVSS 4.0 base severity normalization | Missing |

### Cross-Scanner Correlation

| Metric | Value |
|---|---|
| Scanners Correlated | Nessus, Qualys |
| CWE Taxonomy Source | Missing |
| CWE Top 25 Source | 2024 list |
| CWE Normalization Method | Not documented |
| KEV Weakness Cross-Check | Not performed |
| Total Unique Findings | 18 |
| High Confidence (2+ scanners) | 9 (50%) |
| Conflicts Requiring Investigation | 0 |
| Coverage Gaps | none |

### Why This Fixture Should Be Flagged

This report claims current CWE prioritization while only citing the 2024 CWE Top 25 and omitting CWE taxonomy provenance. It also skips KEV weakness evidence, so the scanner tuning review cannot prove its prioritization model is current.
