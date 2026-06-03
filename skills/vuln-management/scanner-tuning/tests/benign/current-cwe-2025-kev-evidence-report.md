# Scanner Tuning Report Fixture: Current CWE 2025 Evidence

## Scanner Tuning Report
**Date:** 2026-06-03
**Skill:** scanner-tuning v1.0.1
**Frameworks:** CVSS 4.0, CWE, CWE Top 25 2025, CWE Top 10 KEV 2025
**Reviewer:** AI-assisted (human review required for policy changes and severity overrides)

### Evidence Sources

| Evidence Source | Version or Date | Purpose | Status |
|---|---|---|---|
| CWE taxonomy | CWE export checked 2026-06-03 | Cross-scanner weakness classification | Current |
| CWE Top 25 | 2025 list, methodology final pull 2025-11-17 | Advisory prioritization by weakness prevalence and impact | Current |
| CWE Top 10 KEV Weaknesses | 2025 list, page updated 2026-01-27 | Advisory prioritization for exploited weakness patterns | Performed |
| NVD CVSS | 2026-06-03 export | CVSS 4.0 base severity normalization | Current |

### False Positive Analysis

| Plugin/Check ID | CVE ID | FP Pattern | Affected Assets | Evidence | Recommendation |
|---|---|---|---|---|---|
| VM-1001 | CVE-2025-0001 | Banner | 1 host | Authenticated package query shows backported fixed package | Re-scan authenticated |

**Estimated False Positive Rate:** 4%
**Top FP Contributors:** banner-based web server checks

### Cross-Scanner Correlation

| Metric | Value |
|---|---|
| Scanners Correlated | Nessus, Trivy |
| CWE Taxonomy Source | CWE export checked 2026-06-03 |
| CWE Top 25 Source | 2025 list, methodology final pull 2025-11-17 |
| CWE Normalization Method | Original scanner CWE preserved; normalized CWE recorded separately where applicable |
| KEV Weakness Cross-Check | Performed |
| Total Unique Findings | 12 |
| High Confidence (2+ scanners) | 5 (42%) |
| Conflicts Requiring Investigation | 1 |
| Coverage Gaps | container runtime configuration not covered by network scanner |

### Overall Tuning Classification
**Rating:** Tuned
**Rationale:** The report binds severity and prioritization to current source-dated evidence and preserves CWE provenance during correlation.
