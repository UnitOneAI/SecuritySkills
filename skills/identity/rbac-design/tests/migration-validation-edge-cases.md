# RBAC Migration Validation Edge Cases

These fixtures validate that RBAC/ABAC redesigns include migration simulation,
constraint regression, and rollback evidence before production cutover.

## Edge Case 1: New Model Adds Privilege

Input evidence:

```yaml
user: finance-analyst-17
before:
  roles: [finance-reader]
  permissions: [invoice.read, budget.read]
after:
  roles: [finance-analyst]
  permissions: [invoice.read, budget.read, payment.approve]
owner_approval: null
historical_replay: not_run
```

Expected output:

- Finding ID: `RBAC-MIG-01` and `RBAC-MIG-07`
- Severity: High because the migration adds payment approval without owner approval
- Remediation requires explicit owner approval or permission removal before cutover

## Edge Case 2: SoD Regression After Role Merge

Input evidence:

```yaml
role_merge:
  from: [payment-initiator, payment-approver]
  to: finance-operator
constraints:
  ssod_pairs:
    - [payment-initiator, payment-approver]
regression_test:
  status: failed
  violation_count: 12
```

Expected output:

- Finding ID: `RBAC-MIG-03`
- Severity: Critical or High depending on production financial impact
- Do not approve role merge until SoD constraints are enforced or model is redesigned

## Edge Case 3: ABAC Missing Attribute Fails Open

Input evidence:

```yaml
policy: tenant_data_read
condition: subject.tenant_id == resource.tenant_id
test_case:
  subject:
    user: contractor-22
    tenant_id: null
  resource:
    tenant_id: acme
  observed_decision: permit
  expected_decision: deny
decision_log: missing
```

Expected output:

- Finding ID: `RBAC-MIG-05` and `RBAC-MIG-08`
- Severity: High because missing attribute fails open
- Remediation requires fail-closed behavior and auditable policy evaluation logs
