# Vulnerable fixture: metadata auth without method authorization

```proto
syntax = "proto3";

package identity.admin.v1;

service AdminService {
  rpc DeleteUser(DeleteUserRequest) returns (DeleteUserResponse);
}

message DeleteUserRequest {
  string user_id = 1;
}
```

```go
func (s *AdminServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
    caller := auth.FromContext(ctx)
    if caller == nil {
        return nil, status.Error(codes.Unauthenticated, "login required")
    }

    deleted, err := s.store.DeleteUser(ctx, req.UserId)
    if err != nil {
        return nil, status.Error(codes.Internal, "delete failed")
    }
    return &pb.DeleteUserResponse{Deleted: deleted}, nil
}
```

Expected findings:

- API5:2023 Broken Function Level Authorization because any authenticated caller can invoke an admin method.
- API1:2023 Broken Object Level Authorization if `req.UserId` is not constrained to the caller tenant or ownership boundary.
