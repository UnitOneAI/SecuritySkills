# Vulnerable: EPSS and KEV fields without source evidence

This fixture calibrates `DEP-ENRICH-*` findings. The report looks complete, but
it does not prove where the EPSS score or KEV status came from.

```markdown
| # | CVE | Package | Version | Fixed In | CVSS | EPSS | KEV | Priority |
|---|-----|---------|---------|----------|------|------|-----|----------|
| 1 | CVE-2026-12345 | example-lib | 1.2.3 | 1.2.4 | 9.1 | 0.04 | No | P2 |
```

## Expected findings

- `DEP-ENRICH-01`: EPSS/KEV fields lack source URL, scanner metadata, or feed date.
- `DEP-ENRICH-02`: missing KEV evidence is treated as clean `No`.
- Priority should not be downgraded from missing enrichment evidence.
