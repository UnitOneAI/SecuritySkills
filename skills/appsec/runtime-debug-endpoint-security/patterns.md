# Extended Detection Patterns — runtime-debug-endpoint-security

This file contains the full detection-pattern library for the skill. The main `SKILL.md` references this file for patterns that exceed the lean entrypoint limit.

---

## Route Pattern Library (Regex)

### High-Confidence Patterns

| Framework | Pattern | Description |
|---|---|---|
| **Generic (path-based)** | `^/(debug|health|actuator|admin|internal|ops|metrics|diagnostics|dev|test)(/|$)` | Matches common debug/diagnostic path prefixes |
| **Spring Boot Actuator** | `^/actuator/(env|configprops|beans|heapdump|threaddump|logfile|trace|auditevents|httptrace|scheduledtasks|mappings|conditions)` | Sensitive actuator endpoints |
| **Express.js** | `app\.(get|post|put|delete|patch|use)\(['"](/debug|/health|/actuator|/admin|/internal|/ops|/metrics|/diagnostics|/dev|/test)` | Route registration patterns |
| **FastAPI/Starlette** | `@(router|app)\.(get|post|put|delete|patch)\(['"](/debug|/health|/actuator|/admin|/internal|/ops|/metrics|/diagnostics|/dev|/test)` | Route decorator patterns |
| **Go (gin/chi/mux)** | `router\.(GET|POST|PUT|DELETE|PATCH)\(['"](/debug|/health|/actuator|/admin|/internal|/ops|/metrics|/diagnostics|/dev|/test)` | Route registration |
| **.NET (ASP.NET Core)** | `\[Http(Get|Post|Put|Delete|Patch)\]\[.*['"](/debug|/health|/actuator|/admin|/internal|/ops|/metrics|/diagnostics|/dev|/test)` | Attribute routing |
| **Node.js (Fastify)** | `fastify\.(get|post|put|delete|patch)\(['"](/debug|/health|/actuator|/admin|/internal|/ops|/metrics|/diagnostics|/dev|/test)` | Route registration |

### Medium-Confidence Patterns

| Framework | Pattern | Description |
|---|---|---|
| **Feature flag endpoints** | `^/(features|flags|toggles|experiments)(/|$)` | Feature flag management endpoints |
| **Profiling/pprof** | `^/debug/pprof` | Go pprof endpoints |
| **Jolokia/JMX** | `^/jolokia` | Java JMX over HTTP |
| **GraphQL introspection** | `(__schema|__type)` in query | GraphQL schema introspection |
| **Swagger/OpenAPI UI** | `^/swagger(-ui)?(/|$)|^/api-docs(/|$)|^/openapi(/|$)` | API documentation endpoints |

---

## Authorization Absence Patterns

### Java (Spring)

| Pattern | Description |
|---|---|
| Missing `@PreAuthorize` / `@PostAuthorize` / `@Secured` on controller method | No method-level authorization |
| Missing `@EnableGlobalMethodSecurity(prePostEnabled = true)` | Global method security disabled |
| `@RequestMapping` without security config in `WebSecurityConfigurerAdapter` | No URL-level security |
| Actuator `management.endpoints.web.exposure.include=*` without `management.endpoint.health.show-details=never` | Over-exposed actuator |

### JavaScript/TypeScript (Express/Fastify)

| Pattern | Description |
|---|---|
| Route handler without `requireAuth`, `authenticate`, `isAuthenticated` middleware | No auth middleware |
| `app.use('/debug', ...)` without auth middleware mounted | Debug routes unprotected |
| `router.get('/admin/*', handler)` without role check | Admin routes without RBAC |

### Python (FastAPI/Flask/Django)

| Pattern | Description |
|---|---|
| `@router.get("/debug/...")` without `Depends(get_current_user)` or `Security(...)` | No dependency injection for auth |
| `@app.route("/admin/...")` without `@login_required` or `@permission_required` | No decorator-based auth |
| `APIRouter(prefix="/internal", dependencies=[])` — empty dependencies | No global dependencies |

### Go (gin/chi)

| Pattern | Description |
|---|---|
| `router.GET("/debug/...", handler)` without middleware chain | No middleware |
| `r.Group("/admin", handler)` without auth middleware in group | Admin group unprotected |

### C# (ASP.NET Core)

| Pattern | Description |
|---|---|
| `[AllowAnonymous]` on debug/admin endpoint | Explicitly public |
| Missing `[Authorize]` or `[Authorize(Roles="Admin")]` | No authorization attribute |
| `endpoints.MapControllers()` without global authorization policy | No global policy |

---

## Weak Trust Signal Patterns

### Header-Based Trust

| Pattern | Language | Risk |
|---|---|---|
| `req.headers['x-forwarded-for']` / `req.ip` / `request.META['REMOTE_ADDR']` | JS/Python | IP spoofing via proxy headers |
| `req.headers['x-real-ip']` / `request.headers.get('X-Real-IP')` | JS/Python | Header injection |
| `request.headers.get('User-Agent')` for authorization | All | User-Agent spoofing |
| `request.headers.get('X-Custom-Auth')` without validation | All | Custom header trust |

### Feature Flag Trust

| Pattern | Language | Risk |
|---|---|---|
| `if (featureFlags.isEnabled('debug-mode'))` without role check | All | Flag toggle = auth bypass |
| `@FeatureGate("debug")` as sole guard | .NET | Feature flag = authorization |
| `flags.Get("admin-access")` without user context | Go | Flag = permission |

### Context Reuse Patterns

| Pattern | Language | Risk |
|---|---|---|
| `background_tasks.add_task(fn, current_user)` | Python FastAPI | User context in background |
| `Task.Run(() => DoWork(user))` | C# | Captured user in background |
| `go func() { handle(user) }()` | Go | Goroutine captures request user |
| `queue.enqueue(job, user_id)` without re-check | All | Stale authorization |

### Exception Handler Bypass

| Pattern | Language | Risk |
|---|---|---|
| `@ExceptionHandler` / `@ControllerAdvice` returning debug info | Java | Error pages leak stack traces |
| `app.use((err, req, res, next) => { res.json({stack: err.stack}) })` | Express | Stack trace exposure |
| `app.exception_handler(Exception)` returning internal state | FastAPI | Debug info in error response |

---

## Language/Framework Specific Guidance

### Spring Boot (Java)

**Actuator Endpoints to Audit:**
- `/actuator/env` — Environment variables (secrets!)
- `/actuator/configprops` — Configuration properties
- `/actuator/beans` — Spring bean definitions
- `/actuator/heapdump` — Heap dump (memory contents)
- `/actuator/threaddump` — Thread dump
- `/actuator/logfile` — Log file contents
- `/actuator/trace` / `/actuator/httptrace` — Request traces
- `/actuator/auditevents` — Audit events
- `/actuator/mappings` — Request mappings
- `/actuator/conditions` — Auto-configuration report

**Secure Configuration:**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info  # Only expose health/info by default
  endpoint:
    health:
      show-details: when_authorized  # Require auth for details
    env:
      enabled: false  # Disable entirely unless needed
```

### Express.js (Node.js)

**Common Debug Packages to Audit:**
- `express-debug` — Adds `/debug` routes
- `loopback-component-explorer` — API explorer
- `swagger-ui-express` — Swagger UI
- Custom `/debug` middleware

**Secure Pattern:**
```javascript
// Health check - public, minimal
app.get('/health', (req, res) => res.send('OK'));

// Detailed health - authenticated
app.get('/health/detail', requireAuth, requireRole('ADMIN'), detailedHealth);

// Actuator-style - fully protected
app.use('/actuator', requireAuth, requireRole('ADMIN'), actuatorRouter);
```

### FastAPI (Python)

**Common Patterns:**
```python
# Vulnerable: debug endpoint with no auth
@router.get("/debug/request")
async def debug_request(request: Request):
    return {"headers": dict(request.headers), "session": request.session}

# Secure: explicit auth + role check
@router.get("/debug/request")
async def debug_request(
    request: Request,
    current_user: User = Depends(require_role("ADMIN"))
):
    return sanitize_debug_info(request, current_user)
```

**Background Task Pattern:**
```python
# Vulnerable: reuses user without re-check
background_tasks.add_task(process_data, current_user.id)

# Secure: passes job ID, re-checks at execution
job_id = create_job(requested_by=current_user.id)
background_tasks.add_task(process_data, job_id)
```

### Go (Gin)

```go
// Vulnerable: no auth on debug routes
r.GET("/debug/vars", expvar.Handler())  // expvar is dangerous!
r.GET("/debug/pprof/*action", pprof.Index)

// Secure: auth middleware
debug := r.Group("/debug")
debug.Use(authMiddleware(), roleMiddleware("ADMIN"))
debug.GET("/vars", expvar.Handler())
debug.GET("/pprof/*action", pprof.Index)
```

### ASP.NET Core (C#)

```csharp
// Vulnerable: AllowAnonymous on sensitive endpoint
[HttpGet("/debug/env")]
[AllowAnonymous]
public IActionResult GetEnv() => Ok(Environment.GetEnvironmentVariables());

// Secure: Authorize with policy
[HttpGet("/debug/env")]
[Authorize(Policy = "AdminOnly")]
public IActionResult GetEnv() => Ok(Environment.GetEnvironmentVariables());

// Health checks: separate public vs detailed
app.MapHealthChecks("/health", new HealthCheckOptions { 
    Predicate = _ => false,  // Only liveness
    ResponseWriter = WriteMinimalResponse 
});
app.MapHealthChecks("/health/detail", new HealthCheckOptions {
    Predicate = _ => true,  // Full details
    ResponseWriter = WriteDetailedResponse
}).RequireAuthorization("AdminOnly");
```

---

## Control ID Mapping Reference

| Finding Type | OWASP ASVS 4.0.3 | CWE | NIST SP 800-53 |
|---|---|---|---|
| Missing authorization on debug endpoint | V4.2.1, V4.2.2 | CWE-285 (Improper Authorization) | AC-3, AC-6 |
| Weak trust signal (IP/header) for auth | V2.1.1, V2.1.2 | CWE-290 (Authentication Bypass) | IA-2, IA-5 |
| Context reuse in background task | V4.2.3 | CWE-287 (Improper Authentication) | AC-3, AC-6 |
| Exception handler leaks debug info | V7.2.1, V7.2.2 | CWE-209 (Info Exposure) | SI-11, SC-4 |
| Feature flag used as auth | V4.2.1 | CWE-285 | AC-3 |
| Actuator/env exposure | V13.2.1 | CWE-200 (Info Exposure) | SC-4, CM-6 |
| Health endpoint leaks sensitive data | V7.2.1 | CWE-200 | SC-4 |

---

## Search Queries for Code Review

### GitHub Code Search (for repos under review)

```
# Spring Actuator exposure
repo:target/repo "management.endpoints.web.exposure.include=*"

# Express debug routes
repo:target/repo "/debug" "app.get"

# FastAPI debug endpoints
repo:target/repo "@router.get" "/debug"

# Go pprof exposure
repo:target/repo "pprof" "http"

# Feature flag auth bypass
repo:target/repo "featureFlags" "isEnabled"

# Background task user capture
repo:target/repo "background_tasks.add_task" "current_user"
```

---

## Test Cases for Verification

### Test Case 1: Spring Actuator Env Exposure
**Input:** Controller with `@GetMapping("/actuator/env")` no `@PreAuthorize`
**Expected:** Finding with ASVS V4.2.1, CWE-285, remediation adding `@PreAuthorize("hasRole('ADMIN')")`

### Test Case 2: Express Header Trust
**Input:** Handler using `req.headers['x-forwarded-for']` for auth decision
**Expected:** Finding with ASVS V2.1.1, CWE-290, remediation using explicit auth middleware

### Test Case 3: FastAPI Background Task
**Input:** `background_tasks.add_task(fn, current_user.id)` without re-check
**Expected:** Finding with ASVS V4.2.3, CWE-287, remediation passing job ID and re-checking

### Test Case 4: Public Health Check (Should NOT Flag)
**Input:** `@app.get("/health")` returning `{"status": "ok"}`
**Expected:** No finding (legitimate liveness probe)

### Test Case 5: Metrics Endpoint (Context-Dependent)
**Input:** `@app.get("/metrics")` returning Prometheus format
**Expected:** Finding only if metrics contain sensitive labels (user_id, api_key, internal_ip)

---

*This patterns file is loaded on demand by the agent when reviewing code for runtime-debug-endpoint-security findings.*