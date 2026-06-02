# Vulnerable: Session Recording Cannot Be Linked to Checkout

## Scenario

The PAM tool records privileged sessions, but the recording cannot be tied back to the request, approver, vault checkout, or named user.

## Evidence Sample

```text
request_id=CHG-10422 user=bob role=linux-root duration=2h approval=approved
vault_checkout_id=co-7712 account=root target=linux-prod-7 checkout_user=bob checkout_time=2026-06-02T09:00:00Z
recording_id=rec-9911 target=linux-prod-7 protocol=ssh user=unknown ticket_id=null checkout_id=null
siem_events=checkout_forwarded,recording_started
missing_events=session_end,credential_checkin,credential_rotation
```

## Expected Handling

- Flag unlinked recordings as an attribution and auditability gap.
- Require request, checkout, recording, and revoke/check-in identifiers to be cross-referenced.
- Treat partial SIEM forwarding as insufficient for tamper-resistant audit evidence.
