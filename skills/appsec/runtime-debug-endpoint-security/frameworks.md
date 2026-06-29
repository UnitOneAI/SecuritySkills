# Framework-Specific Guidance — runtime-debug-endpoint-security

This file contains language/framework-specific rules and remediation patterns. The main `SKILL.md` references this file for detailed guidance.

---

## Spring Boot (Java)

### Actuator Endpoint Inventory

| Endpoint | Sensitivity | Default Exposure | Recommended |
|---|---|---|---|
| `/actuator/health` | LOW (liveness) | Enabled | Public (minimal) or authenticated (detailed) |
| `/actuator/info` | LOW | Enabled | Public |
| `/actuator/env` | CRITICAL (secrets) | Disabled | Disabled or ADMIN only |
| `/actuator/configprops` | HIGH (config) | Disabled | ADMIN only |
| `/actuator/beans` | MEDIUM | Disabled | ADMIN only |
| `/actuator/heapdump` | CRITICAL (memory) | Disabled | DISABLED |
| `/actuator/threaddump` | MEDIUM | Disabled | ADMIN only |
| `/actuator/logfile` | HIGH (logs) | Disabled | ADMIN only |
| `/actuator/trace` / `/actuator/httptrace` | HIGH (request data) | Disabled | ADMIN only |
| `/actuator/auditevents` | HIGH | Disabled | ADMIN only |
| `/actuator/mappings` | MEDIUM | Disabled | ADMIN only |
| `/actuator/conditions` | MEDIUM | Disabled | ADMIN only |
| `/actuator/scheduledtasks` | LOW | Disabled | ADMIN only |
| `/actuator/flyway` / `/actuator/liquibase` | MEDIUM | Disabled | ADMIN only |

### Secure Configuration (application.yml)

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info  # Minimal exposure
        exclude: env,configprops,beans,heapdump,threaddump,logfile,trace,httptrace,auditevents,mappings,conditions
  endpoint:
    health:
      show-details: when_authorized  # Requires authentication for details
      probes:
        enabled: true  # Separate liveness/readiness
    env:
      enabled: false  # Disable entirely
    configprops:
      enabled: false
    heapdump:
      enabled: false
  health:
    defaults:
      enabled: true
```

### Method-Level Security

```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {
    // Enables @PreAuthorize, @PostAuthorize, @Secured, @RolesAllowed
}

@RestController
@RequestMapping("/actuator")
@PreAuthorize("hasRole('ADMIN')")  // Class-level protection
public class CustomActuatorController {
    
    @GetMapping("/custom-diagnostics")
    @PreAuthorize("hasRole('ADMIN')")  // Method-level (redundant but explicit)
    public Map<String, Object> diagnostics() {
        return Map.of("status", "ok", "timestamp", Instant.now());
    }
}
```

### Common Vulnerability: Custom Debug Endpoints

```java
// VULNERABLE: No auth, exposes internal state
@RestController
@RequestMapping("/debug")
public class DebugController {
    @GetMapping("/request")
    public Map<String, Object> debugRequest(HttpServletRequest request) {
        return Map.of(
            "headers", Collections.list(request.getHeaderNames()),
            "session", request.getSession(false),
            "principal", request.getUserPrincipal()
        );
    }
}

// SECURE: Explicit authorization
@RestController
@RequestMapping("/debug")
@PreAuthorize("hasRole('ADMIN')")
public class DebugController {
    @GetMapping("/request")
    public Map<String, Object> debugRequest(HttpServletRequest request, Principal principal) {
        return Map.of(
            "headers", sanitizeHeaders(Collections.list(request.getHeaderNames())),
            "session", sanitizeSession(request.getSession(false)),
            "principal", principal != null ? principal.getName() : "anonymous"
        );
    }
}
```

---

## Express.js / Fastify (Node.js)

### Middleware Chain Audit

```javascript
// VULNERABLE: Debug routes mounted without auth
app.use('/debug', debugRouter);  // No auth middleware!

// VULNERABLE: Individual routes without auth
app.get('/actuator/env', (req, res) => res.json(process.env));

// SECURE: Auth middleware on all debug/admin routes
const requireAuth = (req, res, next) => {
    if (!req.user) return res.status(401).json({error: 'Unauthorized'});
    next();
};

const requireRole = (...roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
        return res.status(403).json({error: 'Forbidden'});
    }
    next();
};

// Apply to all debug routes
app.use('/debug', requireAuth, requireRole('ADMIN'), debugRouter);
app.use('/actuator', requireAuth, requireRole('ADMIN'), actuatorRouter);
app.use('/admin', requireAuth, requireRole('ADMIN'), adminRouter);

// Health check: public minimal, detailed protected
app.get('/health', (req, res) => res.send('OK'));
app.get('/health/detail', requireAuth, requireRole('ADMIN'), detailedHealth);
```

### Feature Flag Auth Bypass

```javascript
// VULNERABLE: Feature flag as sole authorization
app.get('/debug/feature', (req, res) => {
    if (featureFlags.isEnabled('debug-mode')) {  // Anyone can toggle!
        return res.json(getDebugInfo());
    }
    res.status(404).send('Not found');
});

// SECURE: Feature flag + explicit auth
app.get('/debug/feature', requireAuth, requireRole('ADMIN'), (req, res) => {
    if (!featureFlags.isEnabled('debug-mode')) {
        return res.status(404).send('Not found');
    }
    res.json(getDebugInfo());
});
```

### Background Job Context Reuse

```javascript
// VULNERABLE: Captures req.user in closure
app.post('/admin/trigger', requireAuth, requireRole('ADMIN'), (req, res) => {
    const userId = req.user.id;
    jobQueue.add('sensitive-job', { userId });  // Stale auth!
    res.json({status: 'queued'});
});

// SECURE: Pass job ID, re-verify at execution
app.post('/admin/trigger', requireAuth, requireRole('ADMIN'), async (req, res) => {
    const jobId = await createJob({ requestedBy: req.user.id });
    jobQueue.add('sensitive-job', { jobId });
    res.json({status: 'queued', jobId});
});

// Worker re-verifies
jobQueue.process('sensitive-job', async (job) => {
    const requester = await getUser(job.data.requestedBy);
    if (!await authorize(requester, 'admin:trigger')) {
        throw new Error('Authorization revoked');
    }
    await doSensitiveWork(job.data.jobId);
});
```

---

## FastAPI / Starlette (Python)

### Dependency Injection Audit

```python
# VULNERABLE: No auth dependency
@router.get("/debug/request")
async def debug_request(request: Request):
    return {"headers": dict(request.headers), "session": request.session}

# VULNERABLE: Optional auth (allows unauthenticated)
@router.get("/debug/request")
async def debug_request(request: Request, current_user: User = Depends(get_current_user_optional)):
    if current_user:  # Still executes without user!
        return {"headers": dict(request.headers)}

# SECURE: Required auth + role check
@router.get("/debug/request")
async def debug_request(
    request: Request,
    current_user: User = Depends(require_role("ADMIN"))
):
    return sanitize_debug_info(request, current_user)

# Dependency definitions
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    user = await decode_token(token)
    if not user:
        raise HTTPException(401, "Invalid token")
    return user

async def require_role(required_role: str):
    async def checker(current_user: User = Depends(get_current_user)) -> User:
        if required_role not in current_user.roles:
            raise HTTPException(403, f"Requires {required_role} role")
        return current_user
    return checker
```

### Background Tasks

```python
# VULNERABLE: Reuses user context
@router.post("/admin/trigger-job")
async def trigger_job(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_role("ADMIN"))
):
    background_tasks.add_task(run_sensitive_job, current_user.id)
    return {"status": "queued"}

async def run_sensitive_job(user_id: int):
    # No re-check!
    await sensitive_operation(user_id)

# SECURE: Job ID + re-verification
@router.post("/admin/trigger-job")
async def trigger_job(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_role("ADMIN"))
):
    job_id = await create_job(requested_by=current_user.id)
    background_tasks.add_task(run_sensitive_job, job_id)
    return {"status": "queued", "job_id": job_id}

async def run_sensitive_job(job_id: str):
    job = await get_job(job_id)
    requester = await get_user(job.requested_by)
    if not await authorize(requester, "admin:trigger_job"):
        logger.warning(f"Job {job_id} blocked: requester lost permissions")
        return
    await sensitive_operation(job_id)
```

### Exception Handler Audit

```python
# VULNERABLE: Returns stack trace in production
@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "traceback": traceback.format_exc(),  # LEAKS!
            "request": dict(request.headers)
        }
    )

# SECURE: Minimal error in production, detailed in debug mode
@app.exception_handler(Exception)
async def production_exception_handler(request: Request, exc: Exception):
    if settings.DEBUG:
        return JSONResponse(
            status_code=500,
            content={"error": str(exc), "traceback": traceback.format_exc()}
        )
    # Log internally, return minimal to client
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "request_id": request.headers.get("x-request-id")}
    )
```

---

## Go (Gin / Chi / Standard Library)

### Route Group Protection

```go
// VULNERABLE: Debug routes unprotected
r.GET("/debug/vars", expvar.Handler())
r.GET("/debug/pprof/*action", pprof.Index)
r.GET("/actuator/env", func(c *gin.Context) {
    c.JSON(200, os.Environ())
})

// SECURE: Protected group
debug := r.Group("/debug")
debug.Use(authMiddleware(), roleMiddleware("ADMIN"))
debug.GET("/vars", expvar.Handler())
debug.GET("/pprof/*action", pprof.Index)

actuator := r.Group("/actuator")
actuator.Use(authMiddleware(), roleMiddleware("ADMIN"))
actuator.GET("/env", func(c *gin.Context) {
    c.JSON(200, sanitizeEnv(os.Environ()))
})
```

### Middleware Definitions

```go
func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        user, err := validateToken(token)
        if err != nil {
            c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
            return
        }
        c.Set("user", user)
        c.Next()
    }
}

func roleMiddleware(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user, exists := c.Get("user")
        if !exists {
            c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
            return
        }
        u := user.(*User)
        if !slices.Contains(u.Roles, requiredRole) {
            c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden"})
            return
        }
        c.Next()
    }
}
```

### Background Goroutines

```go
// VULNERABLE: Captures user in goroutine
func triggerJob(c *gin.Context) {
    user := c.MustGet("user").(*User)
    go func() {
        sensitiveOperation(user.ID)  // No re-check!
    }()
    c.JSON(200, gin.H{"status": "queued"})
}

// SECURE: Pass job ID, re-verify in goroutine
func triggerJob(c *gin.Context) {
    user := c.MustGet("user").(*User)
    jobID := createJob(user.ID)
    go func(id string) {
        requester, _ := getUserByJobID(id)
        if !authorize(requester, "admin:trigger") {
            log.Printf("Job %s blocked: auth revoked", id)
            return
        }
        sensitiveOperation(id)
    }(jobID)
    c.JSON(200, gin.H{"status": "queued", "job_id": jobID})
}
```

---

## ASP.NET Core (C#)

### Endpoint Authorization

```csharp
// VULNERABLE: AllowAnonymous on sensitive endpoint
[HttpGet("/debug/env")]
[AllowAnonymous]
public IActionResult GetEnv() => Ok(Environment.GetEnvironmentVariables());

// VULNERABLE: No authorization attribute
[HttpGet("/actuator/configprops")]
public IActionResult GetConfigProps() => Ok(_config.GetAll());

// SECURE: Authorize with policy
[HttpGet("/debug/env")]
[Authorize(Policy = "AdminOnly")]
public IActionResult GetEnv() => Ok(SanitizeEnv(Environment.GetEnvironmentVariables()));

// SECURE: Controller-level + method-level
[ApiController]
[Route("actuator")]
[Authorize(Policy = "AdminOnly")]
public class ActuatorController : ControllerBase
{
    [HttpGet("env")]
    public IActionResult GetEnv() => Ok(SanitizeEnv(_env));
    
    [HttpGet("health")]
    [AllowAnonymous]  // Explicitly public for liveness
    public IActionResult Health() => Ok(new { status = "healthy" });
}
```

### Policy Configuration

```csharp
// Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => 
        policy.RequireRole("Admin"));
    
    options.AddPolicy("DebugAccess", policy =>
        policy.RequireRole("Admin", "DevOps"));
});

// Health checks: separate public vs detailed
builder.Services.AddHealthChecks()
    .AddCheck<LivenessCheck>("liveness")
    .AddCheck<ReadinessCheck>("readiness");

app.MapHealthChecks("/health", new HealthCheckOptions 
{
    Predicate = check => check.Tags.Contains("liveness"),
    ResponseWriter = WriteMinimalResponse
});

app.MapHealthChecks("/health/detail", new HealthCheckOptions 
{
    Predicate = _ => true,
    ResponseWriter = WriteDetailedResponse
}).RequireAuthorization("AdminOnly");
```

### Background Services

```csharp
// VULNERABLE: Captures user in background service
public class JobTriggerService : BackgroundService
{
    private readonly IServiceProvider _services;
    
    public async Task TriggerJobAsync(User user) 
    {
        await _queue.EnqueueAsync(new SensitiveJob { UserId = user.Id });
    }
}

// SECURE: Job ID + re-verification
public class JobTriggerService : BackgroundService
{
    public async Task TriggerJobAsync(User user) 
    {
        var jobId = await _jobService.CreateAsync(user.Id);
        await _queue.EnqueueAsync(new SensitiveJob { JobId = jobId });
    }
}

public class SensitiveJobHandler
{
    public async Task HandleAsync(SensitiveJob job)
    {
        var requester = await _userService.GetAsync(job.RequestedBy);
        if (!await _authz.AuthorizeAsync(requester, "admin:trigger"))
        {
            _logger.LogWarning("Job {JobId} blocked: requester lost permissions", job.JobId);
            return;
        }
        await _sensitiveService.ExecuteAsync(job.JobId);
    }
}
```

---

## Configuration/Environment Patterns to Audit

### Spring Boot
```yaml
# DANGEROUS: Exposes all actuator endpoints
management.endpoints.web.exposure.include=*

# DANGEROUS: Shows all health details unauthenticated
management.endpoint.health.show-details=always

# SAFE: Minimal exposure
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when_authorized
```

### Express.js
```javascript
// DANGEROUS: Mounts debug middleware unconditionally
if (process.env.NODE_ENV !== 'production') {  // Runtime check!
    app.use('/debug', debugMiddleware);
}

// SAFE: Build-time exclusion (webpack/rollup/tree-shaking)
// debugRoutes.ts only imported in dev entry point
```

### FastAPI
```python
# DANGEROUS: Runtime env check
if settings.DEBUG:
    app.include_router(debug_router, prefix="/debug")

# SAFE: Separate app factory for debug
def create_app(debug: bool = False):
    app = FastAPI()
    if debug:
        app.include_router(debug_router)
    return app
```

### Go
```go
// DANGEROUS: Runtime flag
if os.Getenv("DEBUG") == "true" {
    r.GET("/debug/*", debugHandler)
}

// SAFE: Build tags
//go:build debug
// +build debug
package main
// Debug routes only compiled with -tags=debug
```

---

*This frameworks file is loaded on demand by the agent when reviewing code for runtime-debug-endpoint-security findings in specific languages/frameworks.*