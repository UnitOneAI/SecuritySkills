# Alert Triage De-duplication and Suppression Edge Cases

These fixtures validate that alert-triage does not collapse alert storms or
recommend permanent suppressions without ownership, scope, and correlation
evidence.

## Edge Case 1: Same Raw Event, Multiple Tool Notifications

Input evidence:

```yaml
alerts:
  - alert_id: siem-1001
    rule: suspicious_powershell
    raw_event_id: win-4688-abc
    host: ws-17
    user: alice
  - alert_id: edr-9911
    rule: suspicious_powershell
    raw_event_id: win-4688-abc
    host: ws-17
    user: alice
```

Expected output:

- Finding ID: `TRIAGE-DEDUP-01`
- Alerts may be de-duplicated in the case record
- Evidence retains one raw event reference and both alert IDs
- Priority is based on behavior and context, not duplicate count alone

## Edge Case 2: Password Spray Mistaken for Duplicate Noise

Input evidence:

```yaml
rule: failed_login_threshold
time_window_utc: "2026-06-06T08:00:00Z/2026-06-06T08:10:00Z"
distinct_users: 184
distinct_hosts: 1
source_ip: 203.0.113.50
prior_disposition: "false_positive"
prior_disposition_date: "2025-12-01"
```

Expected output:

- Finding ID: `TRIAGE-DEDUP-02` or `TRIAGE-DEDUP-04`
- Do not reuse stale prior disposition
- Treat as possible password spraying until benign cause is proven
- Correlation checks include source IP reputation and successful logons after failures

## Edge Case 3: Broad Suppression Request for Admin Activity

Input evidence:

```yaml
disposition: BTP
activity: authorized_admin_script
affected_assets:
  - domain_controller
  - production_database
proposed_suppression:
  filter: "user_role = admin"
  owner: null
  expiry: null
  rollback: null
  ticket: null
```

Expected output:

- Finding ID: `TRIAGE-SUP-01` and `TRIAGE-SUP-02`
- Suppression is rejected or narrowed
- Required evidence includes change ticket, owner, expiry, rollback path, and exact host/script scope
- Escalate to detection owner before any filter affecting privileged users or critical assets
