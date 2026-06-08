# Vulnerable: Maintenance Note Missing Authorization Evidence

## Alert

- Rule: Suspicious PowerShell execution on production application host
- Timestamp: 2026-06-08T01:27:00Z
- Host: prod-app-07
- User: admin.jordan
- Observed action: powershell.exe -EncodedCommand <redacted>

## Claimed Authorization

- Analyst note: "maintenance"
- Ticket: not provided
- Approved window: not provided
- Approver: not provided
- Approved assets: not provided
- Planned actions: not provided

## Expected Triage Outcome

- Disposition: unresolved suspicious activity
- Priority: P2/P3 depending on local criticality and related events
- Authorization confidence: Low
- Required note: free-text maintenance claims are not enough for BTP closure; request ticket, approver, window, scope, actor, and expected action evidence or escalate to Tier 2.
