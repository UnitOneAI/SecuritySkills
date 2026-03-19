# EPSS Trend Classification

Extracted from the patch-prioritization SKILL.md.

| Trend | Definition | Action |
|---|---|---|
| **Surging** | EPSS increased by >= 0.2 (absolute) or >= 200% (relative) in 30 days | Escalate one SLA tier immediately; flag for out-of-cycle patching |
| **Rising** | EPSS increased by >= 0.05 (absolute) or >= 50% (relative) in 30 days | Monitor closely; prepare patch for next available window |
| **Stable** | EPSS change < 0.05 in 30 days | Maintain current SLA tier |
| **Declining** | EPSS decreased by >= 0.05 in 30 days | May support risk acceptance for Scheduled/Defer tier findings |

## API Reference

EPSS API: `https://api.first.org/data/v1/epss?cve=[CVE-ID]`

Compare current EPSS against 7-day, 30-day, and 90-day historical scores to determine trend.
