# Vulnerable: stale OWASP Top 10 project source

## Scenario

An AppSec PR review cites a stale OWASP Top 10 project URL and does not record when the source was checked:

```markdown
OWASP Top 10 Source: https://owasp.org/www-project-top-10/
Source Date Checked: missing
Source Status: assumed current
```

## Expected Review Result

Treat the framework citation as not source-verified. The reviewer should refresh the source URL,
record the date checked, and avoid presenting the checklist as current when the cited page is
unavailable.
