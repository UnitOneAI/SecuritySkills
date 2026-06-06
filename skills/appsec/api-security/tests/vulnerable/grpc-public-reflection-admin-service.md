# Vulnerable fixture: public reflection exposes privileged RPC inventory

```proto
syntax = "proto3";

package payments.admin.v1;

service AdminService {
  rpc ExportUsers(ExportUsersRequest) returns (ExportUsersResponse);
  rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);
}
```

```go
grpcServer := grpc.NewServer()
adminpb.RegisterAdminServiceServer(grpcServer, adminServer)
healthpb.RegisterHealthServer(grpcServer, healthServer)
reflection.Register(grpcServer)
listenAndServe("0.0.0.0:443", grpcServer)
```

```text
listener_exposure: internet-facing
auth_metadata: optional
reflection: enabled
health_check: unauthenticated
```

Expected findings:

- API8:2023 Security Misconfiguration for public reflection on a privileged service.
- API9:2023 Improper Inventory Management if reflected methods are absent from the service inventory.
