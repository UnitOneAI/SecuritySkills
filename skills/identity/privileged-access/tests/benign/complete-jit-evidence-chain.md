# Benign: Complete JIT Evidence Chain

## Scenario

A sampled privileged session has request, approval, activation, vault checkout, session recording, SIEM forwarding, and revocation evidence.

## Evidence Sample

```text
request_id=CHG-2201 user=carol role=db-admin duration=2h justification=quarterly-index-maintenance approver=dba-manager
approval_event=2026-06-02T08:55:00Z source=servicenow
vault_checkout_id=co-8881 account=db-root target=db-prod-01 checkout_time=2026-06-02T09:00:00Z
recording_id=rec-8881 protocol=ssh start=2026-06-02T09:02:00Z end=2026-06-02T09:41:00Z linked_checkout=co-8881 linked_request=CHG-2201
revoke_event=2026-06-02T11:00:01Z source=pam role_state=inactive
siem_forwarding=approval,checkout,recording_start,recording_end,revoke all forwarded to immutable_log_bucket
```

## Expected Handling

- Treat the sampled session as strong evidence for JIT control operation.
- Preserve the identifiers and timestamps in the evidence-chain table.
- Mark confidence as high when revocation and immutable logging are both verified.
