# RBAC runtime assurance edge cases

These fixtures support `skills/identity/rbac-design/SKILL.md` runtime assurance guidance.

## Vulnerable: PDP outage fails open

```typescript
async function canUpdateInvoice(user, invoice) {
  try {
    return await pdp.evaluate({
      subject: user.id,
      action: "invoice:update",
      resource: invoice.id,
      tenant: invoice.tenantId,
    });
  } catch (error) {
    logger.warn("pdp unavailable", error);
    return true;
  }
}
```

Expected finding: `RBAC-RUNTIME-01`.

Review evidence to request:

- What decision is returned for PDP timeout, connection refused, invalid policy, and indeterminate states?
- Is the denied or indeterminate decision logged with subject, resource, action, tenant, policy version, reason, correlation ID, and enforcement point?
- Is there a negative outage-mode test proving the request is denied?

## Vulnerable: role cache outlives revocation

```go
func EffectiveRoles(userID string) []string {
    return roleCache.GetOrLoad(userID, 24*time.Hour, func() []string {
        return directory.LookupRoles(userID)
    })
}
```

Expected finding: `RBAC-REVOCATION-01` or `RBAC-REVOCATION-02`.

Review evidence to request:

- Maximum TTL for role, attribute, OAuth scope, and session-claim caches.
- Event-driven invalidation path for termination, transfer, SoD exception expiry, and access-review revocation.
- A revocation latency test that proves access is removed within the stated SLA.

## Benign exception: controlled break-glass wildcard role

```yaml
role: incident-break-glass-admin
permissions:
  - "*"
activation:
  requires_ticket: true
  approvers_required: 2
  max_duration: "30m"
  mfa_required: true
audit:
  session_recording: true
  alert_channel: "security-oncall"
  auto_revoke_on_expiry: true
review:
  owner: "security-operations"
  cadence: "quarterly"
```

Expected handling: do not automatically classify as an uncontrolled god role. Verify the exception evidence, then score missing controls under `RBAC-HIER-08`, `RBAC-RUNTIME-*`, or `RBAC-REVOCATION-*`.

Review evidence to request:

- Ticket, approval, MFA, expiry, recording, alert, and auto-revoke proof.
- Scope boundaries by tenant, environment, or workload where applicable.
- Periodic review evidence and last activation record.

## Migration test: policy decision diff before cutover

```yaml
fixtures:
  - subject: "finance-analyst"
    action: "invoice:approve"
    resource_tenant: "acme"
    expected_old: "deny"
    expected_new: "deny"
  - subject: "tenant-support"
    action: "ticket:read"
    resource_tenant: "acme"
    expected_old: "allow"
    expected_new: "allow"
```

Expected finding when absent: `RBAC-TEST-02`.

Review evidence to request:

- Same allow/deny fixtures executed against old and new policy engines.
- Explicit review of any changed decisions before migration.
- Policy version captured in decision logs after cutover.
