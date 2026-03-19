# Dependency Scan Report Template

```
## Dependency Scan Report

**Project**: [name]
**Manifest**: [file path]
**Date**: [scan date]
**Total Dependencies**: [direct] direct, [transitive] transitive

### Vulnerability Findings

| # | CVE | Package | Version | Fixed In | CVSS | EPSS | KEV | Priority |
|---|-----|---------|---------|----------|------|------|-----|----------|
| 1 | ... | ...     | ...     | ...      | ...  | ...  | ... | ...      |

### License Findings

| # | Package | Version | License | Risk Level | Action Required |
|---|---------|---------|---------|------------|-----------------|
| 1 | ...     | ...     | ...     | ...        | ...             |

### Supply Chain Risk Indicators

- [ ] Typosquatting risk detected
- [ ] Packages with no license
- [ ] Packages with install scripts
- [ ] Unmaintained packages (no release in 2+ years)
- [ ] Dependency confusion risk (internal name collisions)

### Recommendations

1. [Prioritized list of remediation actions]
```
