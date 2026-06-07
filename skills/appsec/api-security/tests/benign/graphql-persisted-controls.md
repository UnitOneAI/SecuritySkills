# Benign: bounded persisted GraphQL controls

## Scenario

Production GraphQL endpoint accepts only persisted query hashes from untrusted clients.

```yaml
graphql_controls:
  persisted_queries_required: true
  unknown_hash_behavior: reject_400
  raw_query_documents_from_public_clients: reject_400
  max_depth: 6
  max_complexity: 500
  max_operations_per_request: 1
  json_array_batching: disabled
  alias_limit: 10
  introspection: disabled_in_prod
  playground: disabled_in_prod
  resolver_cost_overrides:
    Order.lineItems: 20
    Search.results: 50
    Report.exportUrl: 100
  subscription_limits:
    max_connections_per_user: 3
    idle_timeout_seconds: 300
    max_events_per_minute: 120
```

## Expected Result

Do not raise `GQL-OPS-*` findings. The endpoint has evidenced persisted-query enforcement, bounded execution cost, alias/operation limits, subscription limits, and resolver cost overrides.
