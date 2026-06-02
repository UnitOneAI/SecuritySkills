# Vulnerable: JIT Approval Without Revocation Proof

## Scenario

A privileged access request is approved and a vault checkout exists, but the role remains active after the approved access window.

## Evidence Sample

```text
request_id=INC-8821 user=alice role=Azure PIM Global Administrator requested_duration=1h approval=approved approver=security-lead
activation_event=2026-06-02T09:00:00Z source=entra_pim
session_recording_id=rec-4412 target=admin.portal.azure.com start=2026-06-02T09:03:00Z end=2026-06-02T09:37:00Z
revocation_event=not_found
post_window_check=2026-06-02T15:00:00Z role_state=still_active
```

## Expected Handling

- Treat approval and activation as insufficient evidence of JIT control effectiveness.
- Require an explicit expiry, revoke, or deactivation event.
- Flag the finding when privileged access remains active after the approved window.
- Lower confidence if only screenshots or request metadata are available.
