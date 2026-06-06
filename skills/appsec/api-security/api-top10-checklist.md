# API Security Top 10 Checklist

This checklist provides a structured approach to securing APIs against the most critical risks, aligned with OWASP API Security Top 10 and modern architectural patterns including gRPC, GraphQL, and Webhooks.

## 1. Broken Object Level Authorization (BOLA)
- [ ] Verify that all API endpoints validate object ownership before returning data.
- [ ] Ensure UUIDs or non-sequential IDs are used where possible.
- [ ] Implement server-side checks for every request, not just client-side validation.
- [ ] **gRPC Specific**: Validate `context` metadata for user identity and enforce object-level checks in service methods.
- [ ] **GraphQL Specific**: Ensure resolvers enforce authorization logic per field, not just at the query level.

## 2. Broken Authentication
- [ ] Enforce strong authentication mechanisms (OAuth 2.0, OIDC, mTLS).
- [ ] Implement rate limiting on authentication endpoints.
- [ ] **Webhook Specific**: Validate webhook signatures (e.g., HMAC-SHA256) and timestamps to prevent replay attacks.
- [ ] **Gateway Specific**: Ensure the API Gateway handles authentication offloading correctly and does not bypass auth for internal services.

## 3. Broken Object Property Level Authorization
- [ ] Restrict data exposure to only necessary fields (avoid over-fetching).
- [ ] **GraphQL Specific**: Disable introspection in production or restrict it to authorized roles.
- [ ] **GraphQL Specific**: Implement depth limiting and complexity analysis to prevent resource exhaustion.
- [ ] **gRPC Specific**: Use strict protobuf definitions and avoid dynamic field access where possible.

## 4. Unrestricted Resource Consumption
- [ ] Implement rate limiting and throttling per user/IP/API key.
- [ ] Set timeouts for long-running operations.
- [ ] **GraphQL Specific**: Enforce query depth limits and complexity scoring.
- [ ] **gRPC Specific**: Configure stream message size limits and timeout policies in the gateway.

## 5. Broken Function Level Authorization
- [ ] Ensure administrative functions are protected by role-based access control (RBAC).
- [ ] **Gateway Specific**: Verify that the gateway enforces method-level restrictions (e.g., blocking POST to read-only endpoints).
- [ ] **Webhook Specific**: Ensure webhook handlers are not exposed to unauthenticated public access.

## 6. Unrestricted Access to Sensitive Business Flows
- [ ] Implement bot detection and CAPTCHA for high-risk flows.
- [ ] Monitor for unusual patterns (e.g., rapid account creation, bulk data export).
- [ ] **gRPC Specific**: Log and monitor high-frequency calls to sensitive service methods.

## 7. Server Side Request Forgery (SSRF)
- [ ] Validate and sanitize all user-supplied URLs.
- [ ] Block access to internal metadata services (e.g., AWS 169.254.169.254).
- [ ] **Webhook Specific**: Validate webhook URLs against a whitelist of allowed domains.

## 8. Security Misconfiguration
- [ ] Disable detailed error messages in production.
- [ ] Ensure secure headers (CSP, HSTS, X-Content-Type-Options) are set.
- [ ] **Gateway Specific**: Verify that the gateway is configured to strip sensitive headers and enforce TLS 1.2+.
- [ ] **gRPC Specific**: Ensure gRPC services are not exposed without TLS (mTLS recommended).

## 9. Improper Inventory Management
- [ ] Maintain an up-to-date inventory of all API endpoints.
- [ ] Deprecate and remove unused or legacy endpoints.
- [ ] **Discovery Specific**: Use automated tools to scan for undocumented endpoints in gRPC and GraphQL schemas.

## 10. Unsafe Consumption of APIs
- [ ] Validate and sanitize data received from third-party APIs.
- [ ] Implement circuit breakers for external dependencies.
- [ ] **Webhook Specific**: Verify the source of incoming webhooks and validate payload integrity.

## Additional Considerations for Modern Architectures

### gRPC Discovery & Gateway Controls
- Ensure gRPC services are registered in a service mesh or discovery mechanism with proper access controls.
- API Gateways must enforce protocol translation rules and validate incoming gRPC-JSON transcoding requests.

### Webhook Authentication
- All webhook endpoints must require signature verification.
- Implement idempotency keys to handle duplicate deliveries.

### GraphQL False-Positive Gaps
- Avoid relying solely on static analysis tools for GraphQL security; use runtime protection (WAF) with GraphQL-specific rules.
- Ensure that "false positives" in security scans are manually reviewed to avoid masking real vulnerabilities in dynamic resolvers.