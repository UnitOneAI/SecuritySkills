# C# and .NET — Threat Modeling Patterns

## Overview
Language-specific supplement for threat-modeling covering ASP.NET Core application architectures, common .NET deployment patterns, and .NET-specific threat vectors.

## .NET Application Architecture Patterns

### Typical ASP.NET Core Web Application
```
Browser → [Kestrel/YARP] → ASP.NET Core Pipeline (Middleware) → Controllers/Minimal APIs → EF Core → SQL Server/PostgreSQL
                                     ↓
                              Identity/Auth Middleware
                                     ↓
                              SignalR WebSockets
                                     ↓
                              Background Services (IHostedService)
```

### Common .NET Deployment Topologies
1. **Kestrel behind reverse proxy** (nginx/YARP) — trust boundaries between proxy and Kestrel
2. **Azure App Service** — trust boundaries with Azure AD, Key Vault, managed identities
3. **Container (Docker/Kubernetes)** — container escape, pod-to-pod communication
4. **Azure Functions / AWS Lambda** — serverless trust boundaries, cold start timing
5. **Blazor WebAssembly** — client-side trust boundary (all client code is untrusted)

## STRIDE Threats Specific to .NET

### Spoofing
1. Forged JWT tokens — misconfigured `TokenValidationParameters`
2. Cookie theft — missing `Secure`, `HttpOnly`, `SameSite` on ASP.NET Core cookies
3. Service-to-service spoofing — missing mTLS between microservices using `HttpClient`
4. Identity provider confusion — multiple auth schemes without proper scheme selection

### Tampering
1. **Model binding over-posting** — attacker adds extra fields to POST body that bind to sensitive model properties
2. **ViewState tampering** (legacy ASP.NET) — if migrating from WebForms
3. **Configuration tampering** — `appsettings.json` writable in deployment, environment variable injection
4. **EF Core query tampering** — raw SQL with user input via `FromSqlRaw`
5. **SignalR message tampering** — missing authorization on hub methods

### Repudiation
1. Missing audit logging for Identity events (login, logout, password change, role change)
2. `ILogger` not configured for structured, centralized logging
3. Missing correlation IDs across microservices

### Information Disclosure
1. **Developer exception page in production** — `UseDeveloperExceptionPage()` leaks stack traces, source code
2. **EF Core query logging** — connection strings and SQL with parameters logged at Debug level
3. **Swagger/OpenAPI in production** — full API schema exposed
4. **Server header** — Kestrel exposes `Server: Kestrel` by default
5. **User secrets** — `secrets.json` not used, secrets in `appsettings.json` committed to git
6. **Blazor WASM** — all client-side code and embedded secrets are extractable

### Denial of Service
1. **Regex DoS** — `new Regex(pattern)` without `RegexOptions.NonBacktracking` (.NET 7+) or timeout
2. **Unbounded model binding** — large JSON payloads, deeply nested objects
3. **SignalR connection exhaustion** — no connection limits
4. **Background service failure** — `IHostedService` crash takes down the host
5. **EF Core N+1 queries** — unoptimized queries causing database exhaustion

### Elevation of Privilege
1. **Missing `[Authorize]` on controllers/hubs** — endpoints default to anonymous
2. **Role claim manipulation** — trusting role claims from JWT without server-side validation
3. **Dependency injection abuse** — registering services with wrong lifetime (singleton with scoped dependency)
4. **Unsafe deserialization** — `BinaryFormatter` allows arbitrary code execution

## .NET-Specific Trust Boundaries

Document trust boundaries unique to .NET applications:
1. **Middleware pipeline order** — authentication must come before authorization; incorrect ordering breaks security
2. **Kestrel to Reverse Proxy** — `ForwardedHeaders` misconfiguration allows IP spoofing
3. **Blazor Server to Client** — SignalR circuit is a trust boundary
4. **Blazor WASM** — entire client app is untrusted; all security must be server-side
5. **EF Core to Database** — parameterized queries are the trust boundary
6. **IHttpClientFactory to External Services** — outbound HTTP is a trust boundary (SSRF, certificate validation)

## .NET Component-Threat Matrix Template

| Component | S | T | R | I | D | E | Key .NET Concern |
|-----------|---|---|---|---|---|---|-----------------|
| ASP.NET Core Pipeline | H | M | M | M | M | H | Middleware ordering, auth bypass |
| Entity Framework Core | L | H | L | M | M | M | SQL injection via FromSqlRaw |
| ASP.NET Core Identity | H | M | H | M | L | H | Credential stuffing, weak config |
| SignalR Hub | M | M | L | M | H | M | Connection exhaustion, auth on methods |
| Blazor WASM | H | H | M | H | L | H | Client-side code fully untrusted |
| Background Services | L | M | L | L | H | M | Crash recovery, resource exhaustion |
| HttpClient (outbound) | L | M | L | M | L | L | SSRF, cert validation |

## Data Flow Diagram — ASP.NET Core Reference Architecture

```
                                    ============ TRUST BOUNDARY: Internet ===========
                                    |                                               |
                              [Browser/Mobile Client]                               |
                                    |                                               |
                                    | HTTPS (TLS 1.2+)                              |
                                    |                                               |
                                    ============ TRUST BOUNDARY: DMZ ================
                                    |                                               |
                              [Reverse Proxy: YARP / nginx]                         |
                                    |                                               |
                                    | HTTP (internal) or HTTPS                      |
                                    |                                               |
                              ============ TRUST BOUNDARY: App Tier ================
                              |                                                     |
                        [ASP.NET Core App (Kestrel)]                                |
                              |         |         |         |                       |
                              |         |         |         |                       |
              ----------------+---------+---------+---------+-------                |
              |               |                   |                |                |
  [Identity Provider]   [SQL Server/PG]     [Redis Cache]   [Message Queue]        |
  [Azure AD /           [via EF Core]       [via IDistributed [Azure Service Bus / |
   IdentityServer]                           Cache]          RabbitMQ via          |
              |               |                   |          MassTransit]           |
              ============ TRUST BOUNDARY: Data Tier ===============                |
                                                  |                                |
                                            [Blob Storage]                         |
                                            [Azure Blob / S3]                      |
                                                                                   |
                              ============ TRUST BOUNDARY: External =================
```

### Trust Boundary Annotations
- **Internet to DMZ**: All input is untrusted. TLS termination occurs at the reverse proxy.
- **DMZ to App Tier**: `ForwardedHeaders` middleware must be configured to trust only the proxy IP. Without this, `X-Forwarded-For` spoofing is possible.
- **App Tier to Identity Provider**: OAuth 2.0 / OIDC flows. Token validation must enforce issuer, audience, and signing key. Nonce validation required for OIDC.
- **App Tier to Database**: EF Core parameterizes queries by default, but `FromSqlRaw` and `ExecuteSqlRaw` bypass this. Use `FromSqlInterpolated` instead.
- **App Tier to Redis**: Connection string may contain credentials. Use TLS-enabled Redis. Cached data integrity depends on network trust.
- **App Tier to Message Queue**: Messages may be tampered with in transit. Sign or encrypt sensitive payloads. Validate message schemas on consumption.
- **App Tier to Blob Storage**: Shared Access Signatures (SAS) tokens must have minimal scope and short expiry. Never generate account-level SAS tokens.

## .NET-Specific Mitigations Reference

| Threat | .NET Mitigation | Implementation |
|--------|----------------|----------------|
| JWT Spoofing | Strict `TokenValidationParameters` | Validate issuer, audience, lifetime, signing key |
| Over-posting | DTO pattern / `[Bind]` attribute | Never bind directly to EF entities |
| SSRF | URL validation + `IHttpClientFactory` | Allowlist schemes and hosts |
| Deserialization RCE | Ban `BinaryFormatter` | Use `System.Text.Json` with strict typing |
| Config secrets | User Secrets + Key Vault | `AddAzureKeyVault()` in configuration |
| Regex DoS | `RegexOptions.NonBacktracking` | .NET 7+ non-backtracking engine |
| SQL Injection | Parameterized queries via EF Core | Use `FromSqlInterpolated`, never `FromSqlRaw` with concatenation |
| Open Redirect | `LocalRedirect()` / `Url.IsLocalUrl()` | Never redirect to user-supplied URLs without validation |
| CSRF | Anti-forgery tokens | `[ValidateAntiForgeryToken]` on state-changing endpoints |
| Header Injection | `ForwardedHeadersOptions` allowlist | Restrict `KnownProxies` and `KnownNetworks` |

## References
- Microsoft Threat Modeling Tool
- Microsoft SDL Threat Modeling
- ASP.NET Core Security documentation
- OWASP .NET Security Cheat Sheet
