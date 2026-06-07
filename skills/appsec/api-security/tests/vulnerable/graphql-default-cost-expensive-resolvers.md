# Vulnerable: expensive resolvers keep default complexity cost

## Scenario

The API has a complexity plugin, but high-cost fields keep the default field cost.

```yaml
complexity_plugin:
  enabled: true
  max_complexity: 1000
resolver_costs:
  User.orders: 1
  Search.results: 1
  Report.exportUrl: 1
  Billing.invoicePdf: 1
runtime_profile:
  Search.results:
    database_queries_per_call: 8
    third_party_calls_per_call: 1
  Report.exportUrl:
    starts_async_export_job: true
```

## Expected Findings

- `GQL-OPS-04` because database fan-out, export, and third-party-call resolvers use default cost weights.
- `GQL-OPS-03` if complexity rejection evidence is not logged or tested.
