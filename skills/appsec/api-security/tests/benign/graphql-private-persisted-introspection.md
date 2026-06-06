# Private Persisted GraphQL Introspection Evidence

This fixture should not be reported as a high-severity GraphQL introspection
finding.

| Control | Evidence |
| --- | --- |
| Exposure | GraphQL endpoint is reachable only through internal VPN and mTLS |
| Authentication | Developer role is required before introspection is enabled |
| Query shape | Production clients use persisted queries only |
| Abuse controls | Depth, complexity, and alias limits are enforced |
| Documentation | Public schema documentation already exposes non-sensitive types |

Expected classification: informational or no finding, depending on the reviewed
environment. Resolver-level authorization and sensitive field exposure must
still be reviewed separately.
