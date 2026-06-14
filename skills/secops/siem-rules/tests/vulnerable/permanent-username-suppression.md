# Vulnerable: permanent username-only suppression

This sample should be reported because the exclusion is permanent and scoped only to a shared account. If an attacker reuses `svc-build`, the rule no longer alerts even when the host, process, command line, or time window differs from the original false positive.

```spl
index=edr sourcetype=process process_name=powershell.exe
| search user!="svc-build"
| stats count by user, host, process_name, command_line
```

Expected finding:

- Severity: P2 or P3 depending on the detection objective.
- Evidence: no owner, ticket, expiry, asset scope, process scope, or residual detection path.
- Remediation: replace the username-only exclusion with a scoped suppression tied to one host/process/change ticket and an expiry date.
