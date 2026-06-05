# WebSocket and SSE Session Boundary Edge Cases

Use these fixtures to calibrate `api-security` findings for streaming API surfaces.

## Vulnerable: Cookie-Authenticated WebSocket Without Origin or Per-Message Authorization

```ts
const wss = new WebSocketServer({ server, path: "/account/events" });

wss.on("connection", (socket, req) => {
  const session = parseCookieSession(req.headers.cookie);
  if (!session?.userId) {
    socket.close(1008, "unauthorized");
    return;
  }

  socket.on("message", raw => {
    const msg = JSON.parse(String(raw));
    subscribe(socket, `tenant:${msg.tenantId}:${msg.channel}`);
  });
});
```

Expected review result:

- Flag API8/API2 if this endpoint is browser-exposed and accepts cookie-authenticated handshakes without an explicit `Origin` allowlist.
- Flag API1/API5 if `tenantId`, object IDs, topics, or commands are selected after connection without per-message or per-subscription authorization.
- Require evidence for reconnect behavior, token expiration, role revocation, account disablement, max connections, message size, and subscription limits.

## Vulnerable: SSE Uses Long-Lived Query Tokens and Weak Cache Controls

```ts
app.get("/events", (req, res) => {
  const claims = verifyJwt(String(req.query.token));
  res.setHeader("Content-Type", "text/event-stream");
  streamTenantEvents(res, String(req.query.tenantId), claims.sub);
});
```

Expected review result:

- Flag API2/API8 if query tokens are long-lived, logged, leaked through referrers, cached, or replayable.
- Require `Cache-Control: no-store` for sensitive streams and redaction for URL/query values in logs and analytics.
- Flag API1 if tenant/channel authorization is not checked against the token claims before streaming.

## Benign: Public Read-Only Status Stream With Controls

```ts
wss.on("connection", (socket, request) => {
  if (request.headers.origin !== "https://app.example.com") {
    socket.close(1008, "origin rejected");
    return;
  }

  socket.send(JSON.stringify({ type: "public_status", value: "ok" }));
  socket.close(1000, "complete");
});
```

Expected review result:

- Do not report as high risk solely because it uses WebSocket.
- Record as informational or no finding when the stream is public, read-only, does not use cookies or tenant/account data, rejects unexpected browser origins, and has connection/message limits.
