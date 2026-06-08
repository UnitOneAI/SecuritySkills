# Benign: Authorized Maintenance Window Match

## Alert

- Rule: Suspicious service restart on production host
- Timestamp: 2026-06-08T02:14:00Z
- Host: prod-api-03
- User: svc-deploy
- Observed action: restart nginx and deploy artifact api-2026.06.08.1

## Authorization Evidence

- Ticket: CHG-48291, approved
- Approved window: 2026-06-08T02:00:00Z to 2026-06-08T03:00:00Z
- Approver: service owner and on-call incident commander
- Approved assets: prod-api-01 through prod-api-05
- Approved actor: svc-deploy from deploy-runner-02
- Planned actions: package install, service restart, health check, rollback if health check fails

## Expected Triage Outcome

- Disposition: Benign True Positive
- Priority: P4 or closure per local policy
- Authorization confidence: High
- Required note: activity matched ticket, window, actor, asset, action, and expected follow-on health checks.
