# Vulnerable: Maintenance Claim Outside Approved Scope

## Alert

- Rule: Suspicious service restart on production database host
- Timestamp: 2026-06-08T04:12:00Z
- Host: prod-db-02
- User: svc-deploy
- Observed action: restart postgresql and add a local admin account

## Claimed Authorization

- Analyst note: "maintenance"
- Ticket: CHG-48291
- Approved window: 2026-06-08T02:00:00Z to 2026-06-08T03:00:00Z
- Approved assets: prod-api-01 through prod-api-05
- Approved actor: svc-deploy from deploy-runner-02
- Planned actions: package install, nginx restart, health check

## Expected Triage Outcome

- Disposition: True Positive or unresolved suspicious activity
- Priority: P2/P3 depending on local criticality
- Authorization confidence: Low
- Required note: timestamp, asset, and action are outside the approved change scope; local admin creation requires escalation.
