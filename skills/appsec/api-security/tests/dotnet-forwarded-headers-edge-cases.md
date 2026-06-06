# ASP.NET Core Forwarded Header Edge Cases

These fixtures verify that the C#/.NET API supplement distinguishes secure reverse-proxy forwarding from header spoofing, ordering, and host-trust gaps.

```yaml
case_id: DOTNET-FWD-01
title: Known proxy and allowed host before auth is controlled
runtime: ".NET 8.0.17"
configuration:
  forwarded_headers:
    - XForwardedFor
    - XForwardedProto
    - XForwardedHost
  known_proxies:
    - 10.0.0.10
  known_networks: []
  allowed_hosts:
    - api.example.com
middleware_order:
  - UseForwardedHeaders
  - UseRouting
  - UseCors
  - UseAuthentication
  - UseAuthorization
security_decisions:
  uses_forwarded_host_for_oauth_callbacks: true
  uses_forwarded_for_for_rate_limit: true
expected_classification:
  status: Benign / controlled
  reason: "Explicit proxy trust, host allowlisting, and correct middleware order are evidenced."
```

```yaml
case_id: DOTNET-FWD-02
title: ForwardedHeaders.All with cleared trust lists is high risk
runtime: ".NET 7"
configuration:
  forwarded_headers:
    - All
  known_proxies_cleared: true
  known_networks_cleared: true
  direct_client_access_to_kestrel_blocked: false
security_decisions:
  uses_forwarded_proto_for_https_redirect: true
  uses_remote_ip_for_rate_limit: true
expected_classification:
  status: High risk
  reason: "Untrusted clients can spoof scheme and client IP because proxy trust lists are cleared."
```

```yaml
case_id: DOTNET-FWD-03
title: Forwarded headers run after authentication and authorization
runtime: ".NET 8"
configuration:
  known_proxies:
    - 10.0.0.10
  allowed_hosts:
    - api.example.com
middleware_order:
  - UseRouting
  - UseAuthentication
  - UseAuthorization
  - UseForwardedHeaders
downstream_controls:
  tenant_resolution_before_forwarding: true
  audit_attribution_before_forwarding: true
expected_classification:
  status: High risk
  reason: "Security controls evaluate pre-forwarded host/scheme/IP because middleware order is wrong."
```

```yaml
case_id: DOTNET-FWD-04
title: Trusted proxy but X-Forwarded-Host lacks host allowlisting
runtime: ".NET 8"
configuration:
  forwarded_headers:
    - XForwardedHost
    - XForwardedProto
  known_proxies:
    - 10.0.0.10
  allowed_hosts: []
  upstream_host_allowlist_evidence: missing
security_decisions:
  generates_password_reset_links: true
  generates_openapi_server_urls: true
expected_classification:
  status: Medium risk
  reason: "Proxy is trusted, but forwarded host influences generated links without host allowlist evidence."
```

```yaml
case_id: DOTNET-FWD-05
title: Managed hosting path supplies forwarded headers safely
runtime: ".NET 9.0.6"
hosting:
  platform: Azure App Service
  aspnetcore_module_or_integration: documented
  direct_kestrel_access_blocked: true
  edge_overwrites_x_forwarded_headers: true
configuration:
  manual_use_forwarded_headers: false
security_decisions:
  uses_forwarded_proto_for_redirects: true
expected_classification:
  status: Benign / controlled
  reason: "Managed hosting integration and edge sanitization document the trust boundary."
```

```yaml
case_id: DOTNET-FWD-06
title: Kubernetes ingress requires CIDR KnownNetworks evidence
runtime: ".NET 8"
hosting:
  platform: Kubernetes
  ingress_controller: nginx
configuration:
  forwarded_headers:
    - XForwardedFor
    - XForwardedProto
  known_proxies: []
  known_networks:
    - 10.42.0.0/16
  ingress_sanitizes_inbound_headers: true
middleware_order:
  - UseForwardedHeaders
  - UseRouting
  - UseRateLimiter
  - UseAuthentication
expected_classification:
  status: Benign / controlled
  reason: "CIDR-based ingress network trust is documented and processing precedes rate limiting/auth."
```

```yaml
case_id: DOTNET-FWD-07
title: Logging-only forwarded headers are lower risk but still need boundary evidence
runtime: ".NET 8"
configuration:
  forwarded_headers:
    - XForwardedFor
  known_proxies: []
  known_networks: []
security_decisions:
  influences_auth: false
  influences_rate_limit: false
  influences_redirects: false
  logging_only: true
expected_classification:
  status: Medium risk
  reason: "Header spoofing affects audit attribution even when not used for authorization."
```
