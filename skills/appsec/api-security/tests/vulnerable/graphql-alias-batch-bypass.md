# Vulnerable: alias and batch fan-out bypass sensitive resolver controls

## Scenario

The gateway rate limit is one request per second, but the GraphQL executor allows many operations and aliases in one HTTP request.

```graphql
query PasswordGuesses {
  a1: login(email: "user@example.com", password: "guess1") { token }
  a2: login(email: "user@example.com", password: "guess2") { token }
  a3: login(email: "user@example.com", password: "guess3") { token }
  a4: login(email: "user@example.com", password: "guess4") { token }
}
```

```yaml
graphql_controls:
  gateway_rate_limit: "1 request/second"
  max_operations_per_request: 10
  alias_limit: unlimited
  sensitive_resolver_throttle:
    login: not_configured
  duplicate_resolver_accounting: false
```

## Expected Findings

- `GQL-OPS-01` because multiple operations per request can bypass request-level throttles.
- `GQL-OPS-02` because alias fan-out is not counted against sensitive resolver throttles.
