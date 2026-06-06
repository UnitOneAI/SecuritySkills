# Benign fixture: internal gRPC service with bounded controls

```proto
syntax = "proto3";

package payments.v1;

service PaymentService {
  rpc GetInvoice(GetInvoiceRequest) returns (Invoice);
}
```

```yaml
listener_exposure: mesh-only
server_reflection: internal-only
mTLS:
  required_between_services: true
  allowed_spiffe_ids:
    - spiffe://prod/ns/billing/sa/api
auth_metadata:
  authorization: required
  x-tenant-id: required
authorization:
  decision_point: unary_interceptor
  policy: caller.tenant_id == request.tenant_id && caller.role in ["billing-reader", "billing-admin"]
resource_controls:
  max_receive_message_bytes: 4194304
  deadline_required: true
  per_peer_concurrency: 32
```

Expected behavior:

- Do not raise a High finding merely because the service has no OpenAPI paths or REST middleware.
- Record the gRPC evidence table and verify the method policy binds caller identity to tenant and role.
