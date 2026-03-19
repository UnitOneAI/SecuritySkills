# Enterprise SLA Tier Matrix

Extracted from the patch-prioritization SKILL.md.

| SLA Tier | Remediation Window | SSVC Decision | EPSS Threshold | KEV Status | CVSS 4.0 Range |
|---|---|---|---|---|---|
| **P0 -- Emergency** | 24 hours | Immediate | >= 0.7 OR active exploitation confirmed | Listed (ransomware: Known) | >= 9.0 Critical |
| **P1 -- Critical** | 72 hours | Immediate or Out-of-Cycle | >= 0.4 | Listed | >= 7.0 High/Critical |
| **P2 -- High** | 14 days | Out-of-Cycle | >= 0.1 | Not listed, PoC available | >= 7.0 High |
| **P3 -- Medium** | 30 days | Scheduled | 0.01 - 0.1 | Not listed | 4.0 - 6.9 Medium |
| **P4 -- Low** | 90 days | Scheduled or Defer | < 0.01 | Not listed | < 4.0 Low |
| **P5 -- Informational** | Next scheduled cycle | Defer | < 0.001 | Not listed | None/Low, no exploit path |

## Tier Assignment Rules

1. **CISA KEV override:** Any CVE on the CISA KEV catalog is automatically P0 for federal agencies (BOD 22-01) and minimum P1 for private sector.
2. **SSVC primacy:** The SSVC decision outcome is the primary driver; EPSS and CVSS serve as secondary validation.
3. **Upward adjustment only:** If EPSS or KEV status indicates higher urgency than the SSVC decision alone, escalate the tier; never use EPSS to downgrade an SSVC Immediate decision.
4. **Asset criticality modifier:** For non-critical assets (dev, test, sandbox), the SLA tier may be relaxed by one level with documented justification.
