# C# and .NET -- API Security Patterns

Language-specific supplement for the `api-security` skill covering ASP.NET Core Web API (controllers and Minimal APIs), GraphQL in .NET (HotChocolate / GraphQL.NET), and gRPC in .NET. All patterns target ASP.NET Core on .NET 6, 7, and 8.

---

## OWASP API Security Top 10:2023 -- .NET Patterns

### API1:2023 -- Broken Object Level Authorization (BOLA)

**CWE:** CWE-285, CWE-639
**Severity:** Critical to High

BOLA is the single most common API vulnerability. In ASP.NET Core it manifests when a controller action or Minimal API endpoint accepts a resource identifier and retrieves the object without verifying the caller owns or is authorized to access it.

#### Controller -- Vulnerable

```csharp
// VULNERABLE: Any authenticated user can access any order by ID
[Authorize]
[HttpGet("orders/{id}")]
public async Task<IActionResult> GetOrder(int id)
{
    var order = await _context.Orders.FindAsync(id);
    if (order == null) return NotFound();
    return Ok(order);
}
```

#### Controller -- Secure

```csharp
[Authorize]
[HttpGet("orders/{id}")]
public async Task<IActionResult> GetOrder(int id)
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var order = await _context.Orders
        .Where(o => o.Id == id && o.UserId == userId)
        .FirstOrDefaultAsync();
    if (order == null) return NotFound();
    return Ok(OrderDto.FromEntity(order));
}
```

#### Minimal API -- Vulnerable

```csharp
// VULNERABLE: No ownership filter
app.MapGet("/orders/{id}", async (int id, AppDbContext db) =>
{
    var order = await db.Orders.FindAsync(id);
    return order is not null ? Results.Ok(order) : Results.NotFound();
}).RequireAuthorization();
```

#### Minimal API -- Secure

```csharp
app.MapGet("/orders/{id}", async (int id, ClaimsPrincipal user, AppDbContext db) =>
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var order = await db.Orders
        .Where(o => o.Id == id && o.UserId == userId)
        .FirstOrDefaultAsync();
    return order is not null ? Results.Ok(OrderDto.FromEntity(order)) : Results.NotFound();
}).RequireAuthorization();
```

#### Resource-Based Authorization with `IAuthorizationService`

For complex ownership models, use ASP.NET Core resource-based authorization instead of inline ownership checks:

```csharp
// Authorization requirement and handler
public class OwnerRequirement : IAuthorizationRequirement { }

public class OrderOwnerHandler : AuthorizationHandler<OwnerRequirement, Order>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OwnerRequirement requirement,
        Order resource)
    {
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (resource.UserId == userId)
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

// In the controller
[Authorize]
[HttpGet("orders/{id}")]
public async Task<IActionResult> GetOrder(int id)
{
    var order = await _context.Orders.FindAsync(id);
    if (order == null) return NotFound();

    var authResult = await _authorizationService
        .AuthorizeAsync(User, order, new OwnerRequirement());
    if (!authResult.Succeeded) return Forbid();

    return Ok(OrderDto.FromEntity(order));
}
```

#### BOLA Review Checklist -- .NET

- [ ] Every endpoint accepting a resource ID includes an ownership or authorization check.
- [ ] EF Core queries include a `Where` clause filtering by the authenticated user, or the action calls `IAuthorizationService.AuthorizeAsync`.
- [ ] Batch/list endpoints filter by user scope (never return unfiltered `DbSet` results).
- [ ] Sequential integer IDs are not exposed externally; prefer GUIDs or opaque identifiers.

---

### API2:2023 -- Broken Authentication

**CWE:** CWE-287, CWE-306
**Severity:** Critical

#### JWT Misconfiguration -- Vulnerable

```csharp
// VULNERABLE: Validation parameters are too permissive
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,          // Accepts tokens from any issuer
            ValidateAudience = false,        // Accepts tokens for any audience
            ValidateLifetime = false,        // Accepts expired tokens
            ValidateIssuerSigningKey = false, // Accepts unsigned tokens
        };
    });
```

#### JWT Configuration -- Secure

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1), // Reduce default 5-minute skew
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
            RequireExpirationTime = true,
            RequireSignedTokens = true,
        };
        // Reject tokens via query string to prevent logging/caching leaks
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                if (context.Request.Query.ContainsKey("access_token"))
                {
                    context.Fail("Tokens via query string are not accepted");
                }
                return Task.CompletedTask;
            }
        };
    });
```

#### API Key Validation Middleware

```csharp
public class ApiKeyMiddleware
{
    private const string ApiKeyHeaderName = "X-Api-Key";
    private readonly RequestDelegate _next;

    public ApiKeyMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, IConfiguration config)
    {
        if (!context.Request.Headers.TryGetValue(ApiKeyHeaderName, out var providedKey))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "API key is required" });
            return;
        }

        var validKey = config["ApiKey"];
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(providedKey!),
                Encoding.UTF8.GetBytes(validKey!)))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Invalid API key" });
            return;
        }

        await _next(context);
    }
}
```

Key points: use `CryptographicOperations.FixedTimeEquals` for constant-time comparison to prevent timing attacks. Never compare API keys with `==` or `string.Equals`.

#### Authentication Review Checklist -- .NET

- [ ] `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, and `ValidateIssuerSigningKey` are all `true`.
- [ ] `ClockSkew` is reduced from the default 5 minutes to 1 minute or less.
- [ ] `RequireSignedTokens` and `RequireExpirationTime` are `true`.
- [ ] JWT signing keys are loaded from secure configuration (Key Vault, environment variables), never hardcoded.
- [ ] API key comparisons use constant-time equality.
- [ ] Token refresh and revocation mechanisms are implemented (short-lived access tokens + refresh tokens or a token blocklist).

---

### API3:2023 -- Broken Object Property Level Authorization

**CWE:** CWE-213, CWE-915
**Severity:** High to Medium

This category covers two problems: exposing properties the user should not see (excessive data exposure) and accepting properties the user should not set (mass assignment / over-posting).

#### Mass Assignment -- Vulnerable

```csharp
// VULNERABLE: Binds directly to the entity -- attacker can set IsAdmin
[HttpPost("users")]
public async Task<IActionResult> CreateUser([FromBody] User user)
{
    _context.Users.Add(user);
    await _context.SaveChangesAsync();
    return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
}

// Entity returned directly -- leaks PasswordHash, InternalNotes, etc.
[HttpGet("users/{id}")]
public async Task<IActionResult> GetUser(int id)
{
    var user = await _context.Users.FindAsync(id);
    return Ok(user);
}
```

#### DTO Projection -- Secure

```csharp
// Input DTO -- only fields the caller is allowed to set
public record CreateUserRequest(string Email, string DisplayName, string Password);

// Output DTO -- only fields the caller is allowed to see
public record UserResponse(int Id, string Email, string DisplayName, DateTime CreatedAt);

[HttpPost("users")]
public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
{
    var user = new User
    {
        Email = request.Email,
        DisplayName = request.DisplayName,
        PasswordHash = _passwordHasher.HashPassword(null!, request.Password),
        IsAdmin = false, // Explicitly set, never from user input
    };
    _context.Users.Add(user);
    await _context.SaveChangesAsync();

    var response = new UserResponse(user.Id, user.Email, user.DisplayName, user.CreatedAt);
    return CreatedAtAction(nameof(GetUser), new { id = user.Id }, response);
}

[HttpGet("users/{id}")]
public async Task<IActionResult> GetUser(int id)
{
    var user = await _context.Users
        .Where(u => u.Id == id)
        .Select(u => new UserResponse(u.Id, u.Email, u.DisplayName, u.CreatedAt))
        .FirstOrDefaultAsync();
    return user is not null ? Ok(user) : NotFound();
}
```

#### `[JsonIgnore]` Is Not Sufficient

```csharp
// RISKY: JsonIgnore can be bypassed if a different serializer is used,
// and it couples security policy to the entity model.
public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = "";
    [JsonIgnore] public string PasswordHash { get; set; } = "";
    [JsonIgnore] public bool IsAdmin { get; set; }
}
// Prefer explicit DTO projection over [JsonIgnore] for security boundaries.
```

#### Property-Level Authorization Review Checklist -- .NET

- [ ] No EF Core entity class is used directly as an API input or output model.
- [ ] Dedicated request DTOs whitelist only the properties the caller may set.
- [ ] Dedicated response DTOs whitelist only the properties the caller may see.
- [ ] `[Bind]` or `[JsonIgnore]` is not used as the sole mass-assignment defense.
- [ ] EF Core queries use `.Select()` projection to avoid loading unneeded columns.

---

### API4:2023 -- Unrestricted Resource Consumption

**CWE:** CWE-770, CWE-799, CWE-400
**Severity:** High to Medium

#### Rate Limiting with `Microsoft.AspNetCore.RateLimiting` (.NET 7+)

```csharp
// Program.cs -- configure rate limiting
builder.Services.AddRateLimiter(options =>
{
    // Global fixed window limiter
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.User?.Identity?.Name
                ?? context.Connection.RemoteIpAddress?.ToString()
                ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));

    // Named policy for sensitive endpoints
    options.AddFixedWindowLimiter("auth", limiterOptions =>
    {
        limiterOptions.PermitLimit = 5;
        limiterOptions.Window = TimeSpan.FromMinutes(15);
        limiterOptions.QueueLimit = 0;
    });

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.Headers.RetryAfter =
            ((int)TimeSpan.FromMinutes(1).TotalSeconds).ToString();
        await context.HttpContext.Response.WriteAsJsonAsync(
            new { error = "Rate limit exceeded. Try again later." },
            cancellationToken);
    };
});

// Apply globally
app.UseRateLimiter();

// Apply named policy to specific endpoints
app.MapPost("/auth/login", HandleLogin).RequireRateLimiting("auth");
```

#### Pagination Enforcement

```csharp
// VULNERABLE: No pagination -- returns entire table
[HttpGet("products")]
public async Task<IActionResult> GetProducts()
{
    var products = await _context.Products.ToListAsync();
    return Ok(products);
}

// SECURE: Enforced pagination with maximum page size
[HttpGet("products")]
public async Task<IActionResult> GetProducts(
    [FromQuery] int page = 1,
    [FromQuery] int pageSize = 20)
{
    pageSize = Math.Clamp(pageSize, 1, 100); // Server-enforced maximum
    page = Math.Max(page, 1);

    var totalCount = await _context.Products.CountAsync();
    var products = await _context.Products
        .OrderBy(p => p.Id)
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .Select(p => new ProductResponse(p.Id, p.Name, p.Price))
        .ToListAsync();

    return Ok(new
    {
        data = products,
        page,
        pageSize,
        totalCount,
        totalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
    });
}
```

#### Request Size Limits

```csharp
// Controller-level: limit request body to 1 MB
[RequestSizeLimit(1_048_576)]
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file) { /* ... */ }

// Kestrel server-level limits in Program.cs
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 10 * 1024 * 1024; // 10 MB global max
    options.Limits.MaxRequestHeaderCount = 50;
    options.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});
```

#### Resource Consumption Review Checklist -- .NET

- [ ] Rate limiting middleware is configured and applied globally or per-endpoint.
- [ ] Authentication and login endpoints have a stricter rate limit policy.
- [ ] All list/search endpoints enforce a server-side maximum page size.
- [ ] `MaxRequestBodySize` is set at Kestrel or endpoint level.
- [ ] File upload endpoints validate size, type, and count before processing.
- [ ] Long-running operations use `CancellationToken` and enforce timeouts.

---

### API5:2023 -- Broken Function Level Authorization (BFLA)

**CWE:** CWE-285
**Severity:** Critical to High

BFLA occurs when administrative or privileged operations are accessible to regular users. In ASP.NET Core this typically means missing `[Authorize]` attributes or overly broad role assignments.

#### Policy-Based Authorization -- Secure

```csharp
// Program.cs -- define policies
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"))
    .AddPolicy("CanManageUsers", policy =>
        policy.RequireClaim("permission", "users:manage"))
    .AddPolicy("InternalService", policy =>
        policy.RequireAuthenticatedUser()
            .RequireClaim("client_type", "internal_service"));

// Controller -- require specific policy
[Authorize(Policy = "AdminOnly")]
[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(int id) { /* ... */ }

    [HttpPost("users/{id}/role")]
    [Authorize(Policy = "CanManageUsers")]
    public async Task<IActionResult> AssignRole(int id, [FromBody] RoleRequest request)
    { /* ... */ }
}
```

#### Minimal API Authorization

```csharp
// Require specific policy on Minimal API endpoints
app.MapDelete("/api/admin/users/{id}", async (int id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user == null) return Results.NotFound();
    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.NoContent();
})
.RequireAuthorization("AdminOnly");

// Group authorization with route groups (.NET 7+)
var adminGroup = app.MapGroup("/api/admin")
    .RequireAuthorization("AdminOnly");

adminGroup.MapGet("/users", async (AppDbContext db) =>
    await db.Users.Select(u => new UserResponse(u.Id, u.Email, u.DisplayName, u.CreatedAt))
        .ToListAsync());

adminGroup.MapDelete("/users/{id}", async (int id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user == null) return Results.NotFound();
    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.NoContent();
});
```

#### BFLA Review Checklist -- .NET

- [ ] Every controller or route group has an `[Authorize]` attribute (deny by default).
- [ ] Administrative endpoints use policy-based authorization, not just `[Authorize]` with no policy.
- [ ] `[AllowAnonymous]` is used sparingly and reviewed for each occurrence.
- [ ] Policies use claims or permissions, not just roles (which can become overly broad).
- [ ] Minimal API endpoint groups apply authorization at the group level.

---

### API6:2023 -- Unrestricted Access to Sensitive Business Flows

**CWE:** CWE-799, CWE-770
**Severity:** Medium

This category covers abuse of legitimate business functionality (ticket scalping, credential stuffing, automated purchases) rather than technical vulnerabilities.

#### Per-Operation Rate Limiting

```csharp
// Named rate limit for purchase operations
builder.Services.AddRateLimiter(options =>
{
    options.AddSlidingWindowLimiter("purchase", limiterOptions =>
    {
        limiterOptions.PermitLimit = 3;
        limiterOptions.Window = TimeSpan.FromHours(1);
        limiterOptions.SegmentsPerWindow = 6;
        limiterOptions.QueueLimit = 0;
    });

    options.AddTokenBucketLimiter("password-reset", limiterOptions =>
    {
        limiterOptions.TokenLimit = 3;
        limiterOptions.ReplenishmentPeriod = TimeSpan.FromHours(1);
        limiterOptions.TokensPerPeriod = 1;
        limiterOptions.QueueLimit = 0;
    });
});

app.MapPost("/checkout", HandleCheckout).RequireRateLimiting("purchase");
app.MapPost("/password-reset", HandlePasswordReset).RequireRateLimiting("password-reset");
```

#### Business Flow Review Checklist -- .NET

- [ ] High-value operations (purchases, account creation, password reset) have dedicated rate limit policies.
- [ ] Bot detection or CAPTCHA is integrated for public-facing flows.
- [ ] Business-critical operations log sufficient detail for abuse detection.

---

### API7:2023 -- Server Side Request Forgery (SSRF)

**CWE:** CWE-918
**Severity:** High

#### `HttpClient` with Unsafe User Input -- Vulnerable

```csharp
// VULNERABLE: User-supplied URL fetched without validation
[HttpPost("fetch-preview")]
public async Task<IActionResult> FetchPreview(
    [FromBody] PreviewRequest request,
    [FromServices] IHttpClientFactory httpClientFactory)
{
    var client = httpClientFactory.CreateClient();
    var response = await client.GetStringAsync(request.Url); // SSRF
    return Ok(new { preview = response[..500] });
}
```

#### URL Validation -- Secure

```csharp
public static class UrlValidator
{
    private static readonly HashSet<string> AllowedSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "http", "https"
    };

    public static bool IsSafeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (!AllowedSchemes.Contains(uri.Scheme))
            return false;

        // Resolve DNS and reject private/reserved IP ranges
        try
        {
            var addresses = Dns.GetHostAddresses(uri.Host);
            foreach (var addr in addresses)
            {
                if (IsPrivateOrReserved(addr))
                    return false;
            }
        }
        catch
        {
            return false; // DNS resolution failure
        }

        return true;
    }

    private static bool IsPrivateOrReserved(System.Net.IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal
            || IPAddress.IsLoopback(address)
            || (bytes.Length == 4 && bytes[0] == 10)                          // 10.0.0.0/8
            || (bytes.Length == 4 && bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) // 172.16.0.0/12
            || (bytes.Length == 4 && bytes[0] == 192 && bytes[1] == 168)     // 192.168.0.0/16
            || (bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254)     // 169.254.0.0/16
            || (bytes.Length == 4 && bytes[0] == 127);                        // 127.0.0.0/8
    }
}

[HttpPost("fetch-preview")]
public async Task<IActionResult> FetchPreview(
    [FromBody] PreviewRequest request,
    [FromServices] IHttpClientFactory httpClientFactory)
{
    if (!UrlValidator.IsSafeUrl(request.Url))
        return BadRequest(new { error = "URL is not allowed" });

    var client = httpClientFactory.CreateClient();
    client.Timeout = TimeSpan.FromSeconds(5);
    var response = await client.GetStringAsync(request.Url);
    return Ok(new { preview = response[..Math.Min(response.Length, 500)] });
}
```

#### SSRF Review Checklist -- .NET

- [ ] Every user-supplied URL is validated for scheme (http/https only), resolved host (no private IPs), and port.
- [ ] `HttpClient` calls set an explicit `Timeout`.
- [ ] Allowlists are preferred over blocklists for permitted domains.
- [ ] DNS rebinding is mitigated by validating the resolved IP, not just the hostname.

---

### API8:2023 -- Security Misconfiguration

**CWE:** CWE-16, CWE-942
**Severity:** High to Medium

#### Swagger/OpenAPI Exposure in Production -- Vulnerable

```csharp
// VULNERABLE: Swagger UI accessible in production
app.UseSwagger();
app.UseSwaggerUI();
```

#### Swagger -- Secure

```csharp
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
```

#### Missing Security Headers Middleware

```csharp
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    context.Response.Headers.Append("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    context.Response.Headers.Append("Cache-Control", "no-store");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Remove("Server");
    context.Response.Headers.Remove("X-Powered-By");
    await next();
});
```

#### CORS Misconfiguration -- Vulnerable

```csharp
// VULNERABLE: Allows any origin
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});
```

#### CORS -- Secure

```csharp
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("https://app.example.com", "https://admin.example.com")
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Authorization", "Content-Type")
              .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
    });
});
```

#### Explicit Response Types

```csharp
// VULNERABLE: No documented response types -- hides the API contract
[HttpGet("users/{id}")]
public async Task<IActionResult> GetUser(int id) { /* ... */ }

// SECURE: Explicit response types for OpenAPI documentation and review
[HttpGet("users/{id}")]
[ProducesResponseType(typeof(UserResponse), StatusCodes.Status200OK)]
[ProducesResponseType(StatusCodes.Status404NotFound)]
[ProducesResponseType(StatusCodes.Status401Unauthorized)]
[Produces("application/json")]
public async Task<IActionResult> GetUser(int id) { /* ... */ }
```

#### Exception Handling -- Avoid Stack Trace Leaks

```csharp
// Program.cs -- use ProblemDetails for consistent, safe error responses
builder.Services.AddProblemDetails();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler(); // Returns ProblemDetails without stack traces
}
```

#### Security Misconfiguration Review Checklist -- .NET

- [ ] Swagger/OpenAPI is disabled or authentication-gated in non-development environments.
- [ ] Security headers middleware is registered before endpoint routing.
- [ ] CORS policy specifies explicit origins, methods, and headers.
- [ ] `Server` and `X-Powered-By` response headers are removed.
- [ ] `UseExceptionHandler` is configured in production to prevent stack trace leakage.
- [ ] Kestrel server limits are set for request body size, header count, and timeouts.
- [ ] All controller actions have `[ProducesResponseType]` attributes.

---

### API9:2023 -- Improper Inventory Management

**CWE:** CWE-1059
**Severity:** Medium

#### API Versioning with `Asp.Versioning.Http`

```csharp
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(2, 0);
    options.AssumeDefaultVersionWhenUnspecified = false; // Force clients to specify
    options.ReportApiVersions = true; // Return api-supported-versions header
    options.ApiVersionReader = ApiVersionReader.Combine(
        new UrlSegmentApiVersionReader(),
        new HeaderApiVersionReader("X-Api-Version"));
}).AddApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});
```

#### Deprecating Endpoints

```csharp
[ApiController]
[Route("api/v{version:apiVersion}/users")]
[ApiVersion("1.0", Deprecated = true)] // Mark as deprecated
[ApiVersion("2.0")]
public class UsersController : ControllerBase
{
    [HttpGet]
    [MapToApiVersion("1.0")]
    [Obsolete("Use v2 endpoint")]
    public IActionResult GetUsersV1() { /* legacy implementation */ }

    [HttpGet]
    [MapToApiVersion("2.0")]
    public IActionResult GetUsersV2() { /* current implementation */ }
}
```

#### Inventory Review Checklist -- .NET

- [ ] API versioning is enabled and enforced (no unversioned endpoints in production).
- [ ] Deprecated versions are marked with `Deprecated = true` and have a sunset timeline.
- [ ] OpenAPI specs are generated for each supported version.
- [ ] Unused or shadow endpoints (debug, test, internal) are removed from production builds.

---

### API10:2023 -- Unsafe Consumption of APIs

**CWE:** CWE-295, CWE-346
**Severity:** Medium to High

#### `HttpClient` Without Response Validation -- Vulnerable

```csharp
// VULNERABLE: Trusting upstream API response without validation
public async Task<ThirdPartyUser?> GetPartnerUser(string partnerId)
{
    var client = _httpClientFactory.CreateClient();
    var response = await client.GetFromJsonAsync<ThirdPartyUser>(
        $"https://partner-api.example.com/users/{partnerId}");
    return response; // No schema validation, no size check
}
```

#### Validated Upstream Consumption -- Secure

```csharp
public async Task<ThirdPartyUser?> GetPartnerUser(string partnerId)
{
    var client = _httpClientFactory.CreateClient("PartnerApi");
    client.Timeout = TimeSpan.FromSeconds(10);

    var response = await client.GetAsync($"/users/{Uri.EscapeDataString(partnerId)}");
    response.EnsureSuccessStatusCode();

    // Enforce response size limit before deserialization
    if (response.Content.Headers.ContentLength > 1_048_576) // 1 MB
        throw new InvalidOperationException("Response too large");

    var user = await response.Content.ReadFromJsonAsync<ThirdPartyUser>(
        new JsonSerializerOptions { MaxDepth = 16 });

    // Validate the deserialized object
    if (user is null || string.IsNullOrWhiteSpace(user.Id))
        throw new InvalidOperationException("Invalid response from partner API");

    return user;
}

// Named HttpClient with base address and certificate validation
builder.Services.AddHttpClient("PartnerApi", client =>
{
    client.BaseAddress = new Uri("https://partner-api.example.com");
    client.DefaultRequestHeaders.Add("Accept", "application/json");
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    // Enforce TLS certificate validation (this is the default -- never disable it)
    ServerCertificateCustomValidationCallback = null,
});
```

#### Unsafe Consumption Review Checklist -- .NET

- [ ] Every `HttpClient` call to an upstream API sets an explicit `Timeout`.
- [ ] Responses are size-checked before deserialization.
- [ ] `JsonSerializerOptions.MaxDepth` is set to prevent deeply nested payloads.
- [ ] TLS certificate validation is never bypassed (no `ServerCertificateCustomValidationCallback = (_, _, _, _) => true`).
- [ ] User-controlled data is never interpolated into upstream URLs without `Uri.EscapeDataString`.

---

## ASP.NET Core Minimal API Security Patterns

Minimal APIs (.NET 7+) have a different surface than controller-based APIs. Security-relevant patterns to review:

### Authorization on Endpoint Groups

```csharp
var api = app.MapGroup("/api").RequireAuthorization();

// Public endpoints opt out explicitly
var publicApi = app.MapGroup("/api/public").AllowAnonymous();
publicApi.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

// Admin group with policy
var admin = api.MapGroup("/admin").RequireAuthorization("AdminOnly");
admin.MapGet("/stats", (AppDbContext db) => /* ... */);
```

### Input Validation with Endpoint Filters

```csharp
// Validation filter for Minimal APIs
public class ValidationFilter<T> : IEndpointFilter where T : class
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var argument = context.Arguments.OfType<T>().FirstOrDefault();
        if (argument is null)
            return Results.BadRequest(new { error = "Request body is required" });

        var validator = context.HttpContext.RequestServices.GetService<IValidator<T>>();
        if (validator is not null)
        {
            var result = await validator.ValidateAsync(argument);
            if (!result.IsValid)
                return Results.ValidationProblem(result.ToDictionary());
        }

        return await next(context);
    }
}

app.MapPost("/orders", async (CreateOrderRequest request, AppDbContext db) =>
{
    // Handler only runs if validation passes
    var order = new Order { ProductId = request.ProductId, Quantity = request.Quantity };
    db.Orders.Add(order);
    await db.SaveChangesAsync();
    return Results.Created($"/orders/{order.Id}", OrderDto.FromEntity(order));
})
.AddEndpointFilter<ValidationFilter<CreateOrderRequest>>()
.RequireAuthorization();
```

### Response Filtering with `TypedResults`

```csharp
// TypedResults provides compile-time safety and automatic OpenAPI metadata
app.MapGet("/users/{id}", async Task<Results<Ok<UserResponse>, NotFound>> (
    int id, ClaimsPrincipal user, AppDbContext db) =>
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var found = await db.Users
        .Where(u => u.Id == id && u.Id.ToString() == userId)
        .Select(u => new UserResponse(u.Id, u.Email, u.DisplayName, u.CreatedAt))
        .FirstOrDefaultAsync();

    return found is not null
        ? TypedResults.Ok(found)
        : TypedResults.NotFound();
}).RequireAuthorization();
```

---

## GraphQL Security in .NET (HotChocolate)

HotChocolate is the most widely used GraphQL server for .NET. The following patterns cover common GraphQL-specific attack vectors.

### Introspection Control

```csharp
// Disable introspection in production
builder.Services
    .AddGraphQLServer()
    .AddQueryType<Query>()
    .AddIntrospectionAllowedRule() // Only allows introspection when explicitly permitted
    .ModifyRequestOptions(options =>
    {
        // Disable introspection in non-development environments
        if (!builder.Environment.IsDevelopment())
        {
            options.IncludeExceptionDetails = false;
        }
    });

// Or conditionally configure:
var gql = builder.Services.AddGraphQLServer().AddQueryType<Query>();
if (builder.Environment.IsDevelopment())
{
    gql.AddIntrospectionAllowedRule();
}
```

### Query Depth and Complexity Limiting

```csharp
builder.Services
    .AddGraphQLServer()
    .AddQueryType<Query>()
    .AddMaxExecutionDepthRule(8)     // Prevent deeply nested queries
    .SetPagingOptions(new PagingOptions
    {
        MaxPageSize = 50,
        DefaultPageSize = 20,
        IncludeTotalCount = false,   // Disable by default (can be expensive)
    })
    .ModifyRequestOptions(options =>
    {
        options.ExecutionTimeout = TimeSpan.FromSeconds(10);
    })
    .UseAutomaticPersistedQueryPipeline() // Require persisted queries in production
    .AddReadOnlyFileSystemQueryStorage("./persisted-queries");
```

### Field-Level Authorization

```csharp
public class UserType : ObjectType<User>
{
    protected override void Configure(IObjectTypeDescriptor<User> descriptor)
    {
        descriptor.Field(u => u.Email)
            .Authorize(["AdminOnly"]); // Only admins can query email

        descriptor.Field(u => u.InternalNotes)
            .Authorize(["AdminOnly"])
            .Description("Internal notes visible only to administrators.");

        // Never expose these fields via GraphQL
        descriptor.Field(u => u.PasswordHash).Ignore();
        descriptor.Field(u => u.SecurityStamp).Ignore();
    }
}

// Or using attributes:
public class Query
{
    [Authorize]
    public IQueryable<Order> GetMyOrders(
        ClaimsPrincipal claimsPrincipal,
        AppDbContext context)
    {
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);
        return context.Orders.Where(o => o.UserId == userId);
    }
}
```

### GraphQL Review Checklist -- .NET

- [ ] Introspection is disabled in production.
- [ ] Maximum query depth is set (recommended: 8 or lower).
- [ ] Execution timeout is configured.
- [ ] Persisted queries are enforced in production (no arbitrary query strings).
- [ ] Field-level `[Authorize]` directives are applied to sensitive fields.
- [ ] Sensitive entity properties are explicitly ignored in the type configuration.
- [ ] Pagination enforces a server-side maximum page size.

---

## gRPC Security in .NET

### mTLS Configuration

```csharp
// Program.cs -- require client certificates
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        https.ClientCertificateValidation = (cert, chain, errors) =>
        {
            // Validate issuer and thumbprint against allowlist
            return errors == System.Net.Security.SslPolicyErrors.None
                && AllowedThumbprints.Contains(cert.Thumbprint);
        };
    });
});
```

### Authorization Interceptors

```csharp
// gRPC service with authorization
[Authorize(Policy = "InternalService")]
public class OrderService : Orders.OrdersBase
{
    public override async Task<OrderResponse> GetOrder(
        GetOrderRequest request, ServerCallContext context)
    {
        var userId = context.GetHttpContext().User
            .FindFirstValue(ClaimTypes.NameIdentifier);
        // Apply BOLA check same as REST
        var order = await _context.Orders
            .Where(o => o.Id == request.OrderId && o.UserId == userId)
            .FirstOrDefaultAsync();

        if (order == null)
            throw new RpcException(new Status(StatusCode.NotFound, "Order not found"));

        return MapToResponse(order);
    }
}
```

### Message Size Limits

```csharp
builder.Services.AddGrpc(options =>
{
    options.MaxReceiveMessageSize = 1 * 1024 * 1024;  // 1 MB
    options.MaxSendMessageSize = 4 * 1024 * 1024;     // 4 MB
    options.EnableDetailedErrors = false;               // No stack traces in production
});
```

### Deadline/Timeout Enforcement

```csharp
// Server-side: enforce deadline
public override async Task<OrderResponse> GetOrder(
    GetOrderRequest request, ServerCallContext context)
{
    // Respect client-set deadline; enforce server maximum
    var deadline = context.Deadline;
    if (deadline == DateTime.MaxValue)
    {
        // Client did not set a deadline -- enforce server-side timeout
        context.CancellationToken.ThrowIfCancellationRequested();
    }

    using var cts = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
    cts.CancelAfter(TimeSpan.FromSeconds(10)); // Server-side max

    var order = await _context.Orders
        .FindAsync(new object[] { request.OrderId }, cts.Token);
    // ...
}

// Client-side: always set a deadline
var client = new Orders.OrdersClient(channel);
var response = await client.GetOrderAsync(
    new GetOrderRequest { OrderId = 42 },
    deadline: DateTime.UtcNow.AddSeconds(5));
```

### gRPC Review Checklist -- .NET

- [ ] mTLS is configured for service-to-service communication.
- [ ] Client certificate validation checks issuer and thumbprint against an allowlist.
- [ ] `[Authorize]` is applied at the service or method level.
- [ ] `MaxReceiveMessageSize` and `MaxSendMessageSize` are explicitly configured.
- [ ] `EnableDetailedErrors` is `false` in production.
- [ ] Server-side timeouts are enforced even when clients omit deadlines.

---

## .NET API Security Detection Patterns (Grep)

Use these patterns to scan C# codebases for common API security issues.

### BOLA -- Missing Ownership Checks

```
# Endpoints that fetch by ID without filtering by user
FindAsync\(.*id\)
\.Find\(.*id\)
# Look for these without a corresponding User/Claims check in the same method
```

### Broken Authentication

```
# Disabled JWT validation
ValidateIssuer\s*=\s*false
ValidateAudience\s*=\s*false
ValidateLifetime\s*=\s*false
ValidateIssuerSigningKey\s*=\s*false
RequireSignedTokens\s*=\s*false
```

### Mass Assignment

```
# Entity types used directly as API input parameters
\[FromBody\]\s+(User|Account|Order|Product|Customer)\s
# Missing DTOs -- returning entities directly
return\s+Ok\(\s*await\s+_context\.\w+\.Find
```

### Missing Authorization

```
# Controllers without Authorize attribute
\[ApiController\][\s\S]*?class\s+\w+Controller(?![\s\S]*?\[Authorize)
# AllowAnonymous on sensitive operations
\[AllowAnonymous\][\s\S]*?(Delete|Create|Update|Admin)
```

### SSRF

```
# User input passed to HttpClient without validation
GetAsync\(.*request\.
GetStringAsync\(.*request\.
PostAsync\(.*request\.Url
new\s+Uri\(.*request\.
```

### Security Misconfiguration

```
# Swagger in production
app\.UseSwagger\(\)(?![\s\S]*?IsDevelopment)
# Overly permissive CORS
AllowAnyOrigin\(\)
# Disabled certificate validation
=> true\s*\}.*ServerCertificateCustomValidation
# Detailed errors in production
IncludeExceptionDetails\s*=\s*true
EnableDetailedErrors\s*=\s*true
```

### Unsafe Upstream Consumption

```
# Missing timeout on HttpClient
CreateClient\(\)(?![\s\S]*?Timeout)
# Disabled TLS validation
ServerCertificateCustomValidationCallback\s*=.*=>\s*true
HttpClientHandler.*ServerCertificateCustomValidation.*true
```

### Rate Limiting Absence

```
# Endpoints without rate limiting (check for presence)
MapPost\(.*login.*\)(?![\s\S]*?RequireRateLimiting)
MapPost\(.*register.*\)(?![\s\S]*?RequireRateLimiting)
MapPost\(.*password.*\)(?![\s\S]*?RequireRateLimiting)
```

---

## References

- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [Microsoft ASP.NET Core Security Documentation](https://learn.microsoft.com/en-us/aspnet/core/security/)
- [Microsoft Rate Limiting Middleware](https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit)
- [HotChocolate GraphQL Security](https://chillicream.com/docs/hotchocolate/security)
- [ASP.NET Core gRPC Authentication](https://learn.microsoft.com/en-us/aspnet/core/grpc/authn-and-authz)
