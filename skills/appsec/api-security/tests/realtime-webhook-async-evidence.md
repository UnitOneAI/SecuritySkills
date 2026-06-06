# Real-Time, Webhook, and Async API Evidence Fixtures

These fixtures exercise the API-RT evidence gate in `SKILL.md`. They are intentionally small so reviewers can distinguish a secure non-request/response API from missing evidence.

```yaml
case: secure-websocket-channel
surface:
  style: websocket
  endpoint: wss://api.example.com/realtime
  inventory_source: websocket_route_table
auth_session:
  wss_required: true
  authenticated_handshake: true
  origin_allowlist:
    - https://app.example.com
  csrf_token_required_on_upgrade: true
  session_revalidated_every_minutes: 10
  disconnect_on_logout: true
authorization:
  per_message_authorization: true
  tenant_binding: true
  object_owner_check: true
message_controls:
  schema_validation: true
  max_payload_bytes: 65536
  per_user_message_rate_limit: 100/min
  replay_nonce_required_for_mutations: true
logging:
  connection_events: true
  authz_failures: true
  validation_failures: true
  payloads_redacted: true
expected_decision: Secure
expected_findings: []
```

```yaml
case: websocket-handshake-only-authorization
surface:
  style: websocket
  endpoint: wss://api.example.com/projects
  inventory_source: websocket_route_table
auth_session:
  wss_required: true
  authenticated_handshake: true
  origin_allowlist:
    - https://app.example.com
  session_revalidated_every_minutes: null
  disconnect_on_logout: false
authorization:
  per_message_authorization: false
  tenant_binding: false
message_controls:
  schema_validation: true
  max_payload_bytes: 65536
  per_user_message_rate_limit: null
expected_decision: Vulnerable
expected_findings:
  - check: API-RT-03
    severity: High
    reason: Persistent channel can survive logout or role changes.
  - check: API-RT-04
    severity: High
    reason: Message actions rely only on initial connection authentication.
```

```yaml
case: cross-site-websocket-cookie-auth
surface:
  style: websocket
  endpoint: wss://api.example.com/chat
  inventory_source: gateway_config
auth_session:
  cookie_backed_auth: true
  authenticated_handshake: true
  origin_allowlist: []
  csrf_token_required_on_upgrade: false
authorization:
  per_message_authorization: true
message_controls:
  schema_validation: true
  max_payload_bytes: 32768
expected_decision: Vulnerable
expected_findings:
  - check: API-RT-02
    severity: High
    reason: Cookie-backed WebSocket upgrade lacks Origin allowlist and CSRF/CSWSH protection.
```

```yaml
case: signed-webhook-raw-body-and-replay
surface:
  style: webhook
  endpoint: /webhooks/payment
  inventory_source: webhook_registry
auth_session:
  sender_identity_bound: true
integrity_freshness:
  verifies_signature_over_raw_body: true
  timestamp_tolerance_seconds: 300
  nonce_or_event_id_replay_cache: true
  idempotency_before_side_effects: true
  key_rotation_supported: true
authorization:
  event_allowlist:
    - payment.succeeded
    - payment.failed
  tenant_mapping_verified: true
logging:
  signature_failures: true
  replay_rejects: true
  payloads_redacted: true
expected_decision: Secure
expected_findings: []
```

```yaml
case: webhook-json-reserialization-signature
surface:
  style: webhook
  endpoint: /webhooks/payment
  inventory_source: route_table
integrity_freshness:
  verifies_signature_over_raw_body: false
  verifies_signature_over_parsed_json: true
  timestamp_tolerance_seconds: null
  nonce_or_event_id_replay_cache: false
  idempotency_before_side_effects: false
authorization:
  event_allowlist: []
expected_decision: Vulnerable
expected_findings:
  - check: API-RT-06
    severity: High
    reason: Signature verification uses parsed JSON and lacks freshness, replay, and idempotency evidence.
  - check: API-RT-07
    severity: Medium
    reason: Event allowlist and safe webhook handling evidence are missing.
```

```yaml
case: async-export-result-cross-user
surface:
  style: async_job
  create_endpoint: POST /exports
  status_endpoint: GET /exports/jobs/{job_id}
  result_endpoint: GET /exports/jobs/{job_id}/result
  inventory_source: worker_manifest
auth_session:
  create_requires_auth: true
authorization:
  job_owner_bound_on_create: true
  status_owner_check: false
  result_owner_check: false
  callback_target_authorized: false
  worker_side_auth_context: missing
resource_controls:
  job_ttl_minutes: 60
  result_url_ttl_minutes: null
  revoke_on_role_change: false
logging:
  result_access_failures: false
expected_decision: Vulnerable
expected_findings:
  - check: API-RT-08
    severity: Critical
    reason: Status/result/callback surfaces are not bound to the initiating principal and tenant.
```

```yaml
case: async-export-complete-lifecycle
surface:
  style: async_job
  create_endpoint: POST /exports
  status_endpoint: GET /exports/jobs/{job_id}
  cancel_endpoint: DELETE /exports/jobs/{job_id}
  result_endpoint: GET /exports/jobs/{job_id}/result
  inventory_source: worker_manifest
auth_session:
  create_requires_auth: true
authorization:
  job_owner_bound_on_create: true
  status_owner_check: true
  cancel_owner_check: true
  result_owner_check: true
  callback_target_authorized: true
  tenant_binding: true
  worker_side_auth_context: propagated
resource_controls:
  job_ttl_minutes: 60
  result_url_ttl_minutes: 5
  queue_limit_per_user: 3
  revoke_on_role_change: true
logging:
  worker_authz_failures: true
  callback_failures: true
  result_access_failures: true
  payloads_redacted: true
expected_decision: Secure
expected_findings: []
```

```yaml
case: not-evaluable-missing-runtime-inventory
surface:
  style: hybrid
  endpoint: unknown
  inventory_source: null
missing_artifacts:
  - websocket_route_table
  - webhook_registry
  - worker_manifest
  - broker_topics
auth_session: null
authorization: null
integrity_freshness: null
resource_controls: null
logging: null
expected_decision: Not Evaluable
expected_findings:
  - check: API-RT-01
    severity: Informational
    reason: Runtime inventory artifacts are missing; do not assume secure or vulnerable behavior.
```
