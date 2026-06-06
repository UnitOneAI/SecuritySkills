# Benign fixture: grpc-gateway route shares method authorization

```proto
syntax = "proto3";

package users.v1;

service UserService {
  rpc GetProfile(GetProfileRequest) returns (Profile) {
    option (google.api.http) = {
      get: "/v1/users/{user_id}/profile"
    };
  }
}
```

```yaml
gateway_route:
  method: GET
  path: /v1/users/{user_id}/profile
  authn: required
grpc_method:
  service: users.v1.UserService
  method: GetProfile
  authn: required
shared_authorization_policy:
  owner_check: request.user_id == caller.user_id || caller.role == "support-agent"
  support_agent_scope: same_tenant_only
reflection: disabled_on_public_listener
```

Expected behavior:

- Do not duplicate REST and gRPC findings when grpc-gateway maps to the same underlying method and policy.
- Verify gateway and direct gRPC calls use the same owner and tenant policy.
