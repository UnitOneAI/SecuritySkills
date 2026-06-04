# Realtime authenticated-state DAST coverage

## Vulnerable: HTTP-authenticated scan misses realtime authorization

```yaml
env:
  contexts:
    - name: "staging-app"
      urls:
        - "https://staging.example.com"
      authentication:
        method: "browser"
        verification:
          method: "response"
          loggedInRegex: "\\Qdashboard\\E"

jobs:
  - type: spider
  - type: activeScan
  - type: report
```

The scan signs in and covers HTTP routes, but it never records evidence for `wss://staging.example.com/ws`, `EventSource('/events')`, Socket.IO rooms, or GraphQL subscriptions. It should be flagged when the application uses realtime channels for tenant events, because logout, stale token reconnect, and cross-tenant subscription behavior are untested.

## Benign: realtime channels have explicit negative auth evidence

```yaml
realtimeTransportEvidence:
  websocket:
    endpoint: "wss://staging.example.com/ws"
    handshakeCases:
      - validSession: "101 Switching Protocols"
      - missingSession: "401 Unauthorized"
      - expiredJwt: "401 Unauthorized"
    subscriptionCases:
      - ownTenant: "allow project:alpha"
      - otherTenant: "deny project:beta"
    reconnectCases:
      - afterLogout: "connection closed"
      - afterRoleRevocation: "subscription denied"
    messageSchemaFuzzing: "scripts/dast/ws-message-corpus.json"
  sse:
    endpoint: "https://staging.example.com/events"
    logoutBehavior: "stream closed before sensitive event delivery"
    revokedTokenBehavior: "403 on reconnect"
```

This should pass because realtime transports are treated as separate authenticated surfaces, negative authorization evidence is explicit, and message-schema fuzzing is documented.
