# Vulnerable fixture: unbounded streaming and missing deadlines

```proto
syntax = "proto3";

package reports.v1;

service ReportService {
  rpc Upload(stream ReportChunk) returns (UploadResult);
  rpc Search(SearchRequest) returns (stream SearchResult);
}
```

```yaml
grpc_server:
  max_receive_message_bytes: unlimited
  deadline_required: false
  stream_rate_limit: none
  per_peer_concurrency: unlimited
  cancellation_propagates_to_storage: false
```

Expected finding:

- API4:2023 Unrestricted Resource Consumption for missing message limits, deadlines, stream limits, concurrency controls, and cancellation handling.
