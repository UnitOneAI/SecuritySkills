# Vulnerable: stale RFC 3227 source citation

## Scenario

A forensic collection report cites RFC 3227 through the stale RFC Editor URL:

```markdown
RFC 3227 source: https://www.rfc-editor.org/rfc/rfc3227
Source status: assumed current
Date checked: missing
```

## Expected Review Result

Report this as not evaluable for source freshness until the reviewer records a reachable
official source, the date checked, and whether the source is current. A stale reference can
undermine legal or regulatory reports even when the volatility order itself is correct.
