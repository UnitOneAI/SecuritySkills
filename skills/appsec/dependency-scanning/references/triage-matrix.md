# Vulnerability Triage: EPSS + CVSS + CISA KEV

## Triage Framework

Not all CVEs carry equal operational risk. Use a three-signal triage model to prioritize remediation:

| Signal | Source | What It Measures | Action Threshold |
|---|---|---|---|
| **CVSS** | NVD / vendor advisory | Technical severity of the flaw | Critical (9.0-10.0) and High (7.0-8.9) warrant immediate review |
| **EPSS** | [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days | Score > 0.1 (10%) indicates elevated real-world risk |
| **CISA KEV** | [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed active exploitation in the wild | Any match requires remediation within the CISA-mandated timeline |

## Triage Decision Matrix

| CVSS | EPSS | KEV Listed | Priority | Action |
|---|---|---|---|---|
| Critical/High | > 0.1 | Yes | P0 - Immediate | Patch or mitigate within 24-48 hours |
| Critical/High | > 0.1 | No | P1 - Urgent | Patch within current sprint |
| Critical/High | <= 0.1 | No | P2 - Scheduled | Patch in next release cycle |
| Medium | > 0.1 | Yes | P1 - Urgent | Patch within current sprint |
| Medium | <= 0.1 | No | P3 - Backlog | Track and remediate opportunistically |
| Low | Any | No | P4 - Monitor | Document and revisit quarterly |

## Enrichment Process

1. Extract CVE identifiers from scanner output (e.g., `npm audit --json`, `pip-audit --format json`, `trivy fs --format json`).
2. Query EPSS scores via `https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX`.
3. Cross-reference against the CISA KEV catalog (available as JSON/CSV at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).
4. Apply the decision matrix above to assign priority.
5. Document each finding with CVE ID, affected package and version, CVSS score, EPSS score, KEV status, and recommended fix version.
