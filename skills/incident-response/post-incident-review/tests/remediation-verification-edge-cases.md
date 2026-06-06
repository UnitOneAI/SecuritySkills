# Remediation Verification Edge Cases

Use these cases to validate that `post-incident-review` does not accept ticket closure as proof that incident root causes have been remediated.

## Case 1: Closed ticket with no control evidence

**Input**

```yaml
incident: exposed admin panel without MFA
root_cause: privileged access policy did not require MFA for admin application
remediation:
  id: REM-001
  ticket: SEC-1842
  status: closed
  owner: identity-team
  action: enable MFA for admin application
verification:
  acceptance_criteria: missing
  config_export: missing
  retest_result: missing
  verifier: missing
  recurrence_monitoring: missing
```

**Expected result**

Fail closure. The PIR must keep the action open or mark it partial until MFA configuration evidence and a successful login test prove the original access path is blocked.

## Case 2: Detection rule added but never tested

**Input**

```yaml
incident: data exfiltration over unusual user agent
root_cause: no alert for high-volume download with rare user agent
remediation:
  id: REM-002
  ticket: DET-778
  status: closed
  action: add SIEM detection
verification:
  rule_id: captured
  test_event: missing
  alert_routing: missing
  on_call_owner: missing
  runbook_link: missing
```

**Expected result**

Fail detection validation. A rule definition alone does not prove that a representative event creates the expected alert, severity, owner assignment, and routing.

## Case 3: Backup remediation without restore validation

**Input**

```yaml
incident: destructive malware wiped file server
root_cause: backups were online and deleted by attacker
remediation:
  id: REM-003
  ticket: DR-220
  status: closed
  action: create immutable backups
verification:
  backup_job: captured
  immutability_policy: captured
  restore_test: missing
  recovery_time_result: missing
  residual_risk: undocumented
```

**Expected result**

Mark closure as partial. The implementation evidence is useful, but corrective control verification requires a restore test and documented recovery result.

## Case 4: Complete closure evidence with recurrence watch

**Input**

```yaml
incident: repeated suspicious admin logins from unmanaged device
root_cause: conditional access policy excluded admin role
remediation:
  id: REM-004
  ticket: IAM-402
  status: ready_for_closure
  action: enforce conditional access for admin role
verification:
  acceptance_criteria: admin login from unmanaged device must fail
  config_export: captured
  retest_result: pass
  verifier: security-engineering
  detection_test: alert routes to soc-primary queue
  closure_approver: ciso-delegate
recurrence_monitoring:
  watch_period: 60 days
  query: failed and blocked admin logins from unmanaged devices
  owner: soc-detection
  success_criteria: blocked attempts alert and no successful bypasses
  escalation: reopen REM-004 if bypass succeeds or alert fails
```

**Expected result**

Pass closure. The action has clear acceptance criteria, implementation evidence, independent validation, detection validation, approval, and recurrence monitoring.
