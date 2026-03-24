# C# and .NET — OWASP Top 10:2021 Patterns

## Overview

Language-specific supplement for `owasp-top-10-web` covering ASP.NET Core, Entity Framework Core, Blazor, Razor Pages, and .NET 6+ security patterns. All code examples target .NET 6+ with minimal hosting model or standard ASP.NET Core conventions.

---

## Detection Patterns and Mitigations by Category

### A01:2021 — Broken Access Control

**Detection Patterns (Grep):**

```
# Missing [Authorize] on controllers
\[ApiController\](?!.*\[Authorize\])

# CORS allow all origins
\.AddCors.*AllowAnyOrigin

# IDOR — user-supplied ID without ownership check
FromRoute.*id|FromQuery.*id

# Missing anti-forgery token validation
\[HttpPost\](?!.*\[ValidateAntiForgeryToken\])

# AllowAnonymous on sensitive endpoints
\[AllowAnonymous\]

# Direct file access patterns
Path\.Combine.*Request|PhysicalFile.*Request
```

**Vulnerable Patterns and Secure Alternatives:**

**1. Controller without `[Authorize]` attribute**

```csharp
// VULNERABLE — no authorization on the controller or action
[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> GetOrder(int id)
    {
        var order = await _context.Orders.FindAsync(id);
        return Ok(order);
    }
}
```

```csharp
// SECURE — [Authorize] enforced; ownership validated
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class OrdersController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> GetOrder(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var order = await _context.Orders
            .Where(o => o.Id == id && o.UserId == userId)
            .FirstOrDefaultAsync();

        if (order is null)
            return NotFound();

        return Ok(order);
    }
}
```

**2. CORS misconfiguration**

```csharp
// VULNERABLE — allows any origin with credentials (browser will block, but signals intent issues)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // runtime error, but AllowAnyOrigin alone is risky
    });
});
```

```csharp
// SECURE — explicit allowed origins
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("https://app.example.com", "https://admin.example.com")
              .AllowCredentials()
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Content-Type", "Authorization");
    });
});
```

**3. Direct object reference without ownership validation (IDOR)**

```csharp
// VULNERABLE — any authenticated user can delete any account
[HttpDelete("api/accounts/{id}")]
[Authorize]
public async Task<IActionResult> DeleteAccount(int id)
{
    var account = await _context.Accounts.FindAsync(id);
    _context.Accounts.Remove(account!);
    await _context.SaveChangesAsync();
    return NoContent();
}
```

```csharp
// SECURE — ownership check before modification
[HttpDelete("api/accounts/{id}")]
[Authorize]
public async Task<IActionResult> DeleteAccount(int id)
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var account = await _context.Accounts
        .FirstOrDefaultAsync(a => a.Id == id && a.OwnerId == userId);

    if (account is null)
        return NotFound();

    _context.Accounts.Remove(account);
    await _context.SaveChangesAsync();
    return NoContent();
}
```

**4. Missing `[ValidateAntiForgeryToken]`**

```csharp
// VULNERABLE — POST action in Razor Pages / MVC without anti-forgery validation
[HttpPost]
public IActionResult TransferFunds(TransferModel model)
{
    _bankService.Transfer(model.FromAccount, model.ToAccount, model.Amount);
    return RedirectToAction("Success");
}
```

```csharp
// SECURE — anti-forgery token validated
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult TransferFunds(TransferModel model)
{
    _bankService.Transfer(model.FromAccount, model.ToAccount, model.Amount);
    return RedirectToAction("Success");
}

// Or globally in Program.cs:
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});
```

---

### A02:2021 — Cryptographic Failures

**Detection Patterns (Grep):**

```
# Weak hashing
MD5\.Create|SHA1\.Create|SHA1Managed|MD5CryptoServiceProvider

# Insecure random number generator
new Random\(|System\.Random

# Hardcoded secrets in config
"Password=|"pwd=|"ConnectionString.*password

# Deprecated crypto
RijndaelManaged|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider

# Missing HTTPS enforcement
UseHttpsRedirection.*//|#.*UseHttpsRedirection

# Weak TLS
SslProtocols\.Tls\b|SslProtocols\.Tls11|SslProtocols\.Ssl
```

**Vulnerable Patterns and Secure Alternatives:**

**1. Weak hashing algorithms for security purposes**

```csharp
// VULNERABLE — MD5/SHA1 are broken for security use
using var md5 = MD5.Create();
byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
```

```csharp
// SECURE — use bcrypt/Argon2 for passwords; SHA-256+ for integrity
// For passwords — use ASP.NET Core Identity (PBKDF2 internally) or BCrypt:
var hasher = new PasswordHasher<ApplicationUser>();
string hashed = hasher.HashPassword(user, plainTextPassword);
var result = hasher.VerifyHashedPassword(user, hashed, providedPassword);

// For integrity checks — use SHA-256 or SHA-512:
byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(data));
```

**2. `System.Random` for security-sensitive values**

```csharp
// VULNERABLE — System.Random is predictable
var random = new Random();
string token = random.Next(100000, 999999).ToString();
```

```csharp
// SECURE — cryptographically secure RNG
using System.Security.Cryptography;
string token = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();

// For generating random bytes (e.g., session tokens):
byte[] tokenBytes = RandomNumberGenerator.GetBytes(32);
string tokenBase64 = Convert.ToBase64String(tokenBytes);
```

**3. Hardcoded connection strings with passwords**

```json
// VULNERABLE — password in appsettings.json (committed to source control)
{
  "ConnectionStrings": {
    "Default": "Server=db.example.com;Database=app;User Id=sa;Password=P@ssw0rd123;"
  }
}
```

```csharp
// SECURE — use environment variables, Azure Key Vault, or User Secrets
// In development:
// dotnet user-secrets set "ConnectionStrings:Default" "Server=..."

// In production — Azure Key Vault:
builder.Configuration.AddAzureKeyVault(
    new Uri("https://myvault.vault.azure.net/"),
    new DefaultAzureCredential());

// Or environment variable:
// ConnectionStrings__Default=Server=...
```

**4. Missing HTTPS redirection and HSTS**

```csharp
// VULNERABLE — no HTTPS enforcement
var app = builder.Build();
app.UseRouting();
// Missing: app.UseHttpsRedirection();
// Missing: app.UseHsts();
app.MapControllers();
app.Run();
```

```csharp
// SECURE — enforce HTTPS and HSTS
var app = builder.Build();
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
app.UseHttpsRedirection();
app.UseRouting();
app.MapControllers();
app.Run();
```

**5. Deprecated `RijndaelManaged`**

```csharp
// VULNERABLE — RijndaelManaged is obsolete
using var aes = new RijndaelManaged();
aes.KeySize = 256;
```

```csharp
// SECURE — use Aes.Create()
using var aes = Aes.Create();
aes.KeySize = 256;
aes.GenerateKey();
aes.GenerateIV();

using var encryptor = aes.CreateEncryptor();
// For authenticated encryption, prefer AesGcm:
using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
```

**6. Weak TLS configuration in Kestrel**

```csharp
// VULNERABLE — allows TLS 1.0/1.1
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(https =>
    {
        https.SslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;
    });
});
```

```csharp
// SECURE — TLS 1.2+ only
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(https =>
    {
        https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
    });
});
```

---

### A03:2021 — Injection

**Detection Patterns (Grep):**

```
# SQL injection via EF Core raw SQL
FromSqlRaw\(.*\$"|FromSqlRaw\(.*\+|FromSqlRaw\(.*String\.Format
ExecuteSqlRaw\(.*\$"|ExecuteSqlRaw\(.*\+

# SQL injection via ADO.NET
SqlCommand\(.*\$"|SqlCommand\(.*\+
CommandText.*=.*\$"|CommandText.*=.*\+

# OS command injection
Process\.Start\(.*\$"|Process\.Start\(.*\+|ProcessStartInfo\(.*\$"

# LDAP injection
DirectorySearcher.*\$"|SearchFilter.*\$"

# XSS via Razor
Html\.Raw\(
@\(new MarkupString\(

# XXE
XmlDocument|XmlTextReader|XmlReader\.Create(?!.*DtdProcessing\.Prohibit)
DtdProcessing\.Parse
```

**Vulnerable Patterns and Secure Alternatives:**

**1. SQL Injection via `FromSqlRaw` with string interpolation**

```csharp
// VULNERABLE — string interpolation parsed as raw SQL, not parameterized
string category = userInput;
var products = _context.Products
    .FromSqlRaw($"SELECT * FROM Products WHERE Category = '{category}'")
    .ToList();
```

```csharp
// SECURE — use FromSqlInterpolated (auto-parameterizes) or FromSql (.NET 7+)
var products = _context.Products
    .FromSqlInterpolated($"SELECT * FROM Products WHERE Category = {category}")
    .ToList();

// Or with explicit parameters in FromSqlRaw:
var products = _context.Products
    .FromSqlRaw("SELECT * FROM Products WHERE Category = {0}", category)
    .ToList();

// Best: use LINQ (no raw SQL needed)
var products = await _context.Products
    .Where(p => p.Category == category)
    .ToListAsync();
```

**2. SQL Injection via ADO.NET `SqlCommand`**

```csharp
// VULNERABLE — string concatenation in SQL
using var cmd = new SqlCommand(
    "SELECT * FROM Users WHERE Username = '" + username + "' AND Password = '" + password + "'",
    connection);
using var reader = cmd.ExecuteReader();
```

```csharp
// SECURE — parameterized query
using var cmd = new SqlCommand(
    "SELECT * FROM Users WHERE Username = @Username AND Password = @Password",
    connection);
cmd.Parameters.AddWithValue("@Username", username);
cmd.Parameters.AddWithValue("@Password", password);
using var reader = await cmd.ExecuteReaderAsync();
```

**3. OS Command Injection via `Process.Start`**

```csharp
// VULNERABLE — user input in shell command
[HttpPost("convert")]
public IActionResult Convert(string filename)
{
    Process.Start("bash", $"-c \"convert {filename} output.png\"");
    return Ok();
}
```

```csharp
// SECURE — pass arguments as separate items, validate input
[HttpPost("convert")]
public IActionResult Convert(string filename)
{
    // Validate filename: alphanumeric, known extension, no path traversal
    if (!Regex.IsMatch(filename, @"^[a-zA-Z0-9_-]+\.(jpg|png|gif)$"))
        return BadRequest("Invalid filename");

    var psi = new ProcessStartInfo
    {
        FileName = "/usr/bin/convert",
        ArgumentList = { filename, "output.png" }, // ArgumentList escapes properly
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    using var process = Process.Start(psi);
    process?.WaitForExit();
    return Ok();
}
```

**4. LDAP Injection via `DirectorySearcher`**

```csharp
// VULNERABLE — unescaped user input in LDAP filter
var searcher = new DirectorySearcher(entry);
searcher.Filter = $"(&(objectClass=user)(uid={userInput}))";
```

```csharp
// SECURE — escape special LDAP characters
string SafeLdapFilter(string input)
{
    return input
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}

var searcher = new DirectorySearcher(entry);
searcher.Filter = $"(&(objectClass=user)(uid={SafeLdapFilter(userInput)}))";
```

**5. XSS via `Html.Raw()` in Razor views**

```html
<!-- VULNERABLE — renders unescaped HTML from user data -->
<div>@Html.Raw(Model.UserBio)</div>
```

```html
<!-- SECURE — Razor auto-encodes by default; use @Model directly -->
<div>@Model.UserBio</div>

<!-- If HTML rendering is required, sanitize server-side first -->
@Html.Raw(HtmlSanitizer.Sanitize(Model.UserBio))
<!-- Use a library like HtmlSanitizer (Ganss.Xss) for sanitization -->
```

**6. XSS via `MarkupString` in Blazor**

```csharp
// VULNERABLE — renders raw HTML from user input in Blazor
@((MarkupString)userProvidedContent)
```

```csharp
// SECURE — sanitize before rendering, or avoid raw markup
@((MarkupString)HtmlSanitizer.Sanitize(userProvidedContent))

// Better: use Blazor components and data binding (auto-encoded)
<p>@userProvidedContent</p>
```

**7. XML External Entity (XXE) via `XmlDocument`**

```csharp
// VULNERABLE — DTD processing enabled by default in older code
var xmlDoc = new XmlDocument();
xmlDoc.LoadXml(userSuppliedXml);
```

```csharp
// SECURE — disable DTD processing
var xmlDoc = new XmlDocument
{
    XmlResolver = null // disables external entity resolution
};
xmlDoc.LoadXml(userSuppliedXml);

// Or use XmlReader with safe settings:
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
using var reader = XmlReader.Create(new StringReader(userSuppliedXml), settings);
```

---

### A04:2021 — Insecure Design

**Detection Patterns (Grep):**

```
# Missing rate limiting middleware
# (absence of the following indicates a gap)
AddRateLimiter|UseRateLimiter

# Missing model validation
\[HttpPost\](?!.*\[FromBody\].*\bValidat)
ModelState\.IsValid

# Unrestricted file upload
IFormFile(?!.*ContentType|.*Length|.*Extension)
```

**Vulnerable Patterns and Secure Alternatives:**

**1. Missing rate limiting**

```csharp
// VULNERABLE — no rate limiting on authentication endpoint
app.MapPost("/api/auth/login", async (LoginRequest request, IAuthService auth) =>
{
    var result = await auth.LoginAsync(request.Email, request.Password);
    return result.Succeeded ? Results.Ok(result.Token) : Results.Unauthorized();
});
```

```csharp
// SECURE — rate limiting with Microsoft.AspNetCore.RateLimiting (.NET 7+)
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("auth", config =>
    {
        config.PermitLimit = 5;
        config.Window = TimeSpan.FromMinutes(1);
        config.QueueLimit = 0;
    });
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

app.UseRateLimiter();

app.MapPost("/api/auth/login", async (LoginRequest request, IAuthService auth) =>
{
    var result = await auth.LoginAsync(request.Email, request.Password);
    return result.Succeeded ? Results.Ok(result.Token) : Results.Unauthorized();
}).RequireRateLimiting("auth");
```

**2. Business logic flaw — no transaction or state validation in multi-step workflow**

```csharp
// VULNERABLE — no validation that prior step completed; no atomicity
[HttpPost("checkout/pay")]
public async Task<IActionResult> Pay(PaymentRequest request)
{
    await _paymentService.ChargeAsync(request);
    await _orderService.MarkPaidAsync(request.OrderId);
    return Ok();
}
```

```csharp
// SECURE — validate state machine transitions; use transactions
[HttpPost("checkout/pay")]
public async Task<IActionResult> Pay(PaymentRequest request)
{
    var order = await _orderService.GetAsync(request.OrderId);
    if (order is null || order.Status != OrderStatus.PendingPayment)
        return BadRequest("Order is not in a payable state.");

    await using var transaction = await _context.Database.BeginTransactionAsync();
    try
    {
        await _paymentService.ChargeAsync(request);
        await _orderService.MarkPaidAsync(request.OrderId);
        await transaction.CommitAsync();
        return Ok();
    }
    catch
    {
        await transaction.RollbackAsync();
        throw;
    }
}
```

**3. Missing input validation**

```csharp
// VULNERABLE — no validation on model
public class CreateUserRequest
{
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
}
```

```csharp
// SECURE — Data Annotations for validation
public class CreateUserRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string Email { get; set; } = "";

    [Required]
    [MinLength(12)]
    [MaxLength(128)]
    public string Password { get; set; } = "";
}

// In the controller / minimal API, always check validation:
[HttpPost]
public IActionResult CreateUser([FromBody] CreateUserRequest request)
{
    if (!ModelState.IsValid)
        return ValidationProblem(ModelState);
    // ...
}
```

---

### A05:2021 — Security Misconfiguration

**Detection Patterns (Grep):**

```
# Developer exception page in production
UseDeveloperExceptionPage

# Debug/development environment leaked
ASPNETCORE_ENVIRONMENT.*Development

# Default or weak Identity password requirements
RequireDigit\s*=\s*false|RequiredLength\s*=\s*[1-5]\b|RequireUppercase\s*=\s*false

# Missing security headers
# (absence check — grep for these to confirm they exist)
X-Content-Type-Options|X-Frame-Options|Content-Security-Policy

# Swagger/OpenAPI exposed unconditionally
UseSwagger\(\)|UseSwaggerUI\(\)

# Server header exposed
AddServerHeader\s*=\s*true
```

**Vulnerable Patterns and Secure Alternatives:**

**1. `UseDeveloperExceptionPage()` in production**

```csharp
// VULNERABLE — developer exception page exposes stack traces, source code, env vars
var app = builder.Build();
app.UseDeveloperExceptionPage(); // always active regardless of environment
```

```csharp
// SECURE — only in development; use generic error handler in production
var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}
```

**2. Default Identity password policy too weak**

```csharp
// VULNERABLE — trivially brute-forceable passwords accepted
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 4;
    options.Password.RequireDigit = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
});
```

```csharp
// SECURE — strong password policy
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredUniqueChars = 4;
});
```

**3. Missing security headers**

```csharp
// SECURE — add security headers via middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "0"); // modern recommendation: disable, rely on CSP
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none';");
    context.Response.Headers.Append("Permissions-Policy",
        "camera=(), microphone=(), geolocation=()");
    await next();
});
```

**4. Swagger/OpenAPI exposed in production**

```csharp
// VULNERABLE — Swagger available to all users in all environments
app.UseSwagger();
app.UseSwaggerUI();
```

```csharp
// SECURE — restrict to development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
```

**5. Kestrel server header not removed**

```csharp
// SECURE — suppress the Server header
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
});
```

**6. Overly permissive CORS — see A01 above for examples.**

---

### A06:2021 — Vulnerable and Outdated Components

**Detection Patterns (CLI commands):**

```bash
# Check for NuGet packages with known vulnerabilities
dotnet list package --vulnerable

# Check for deprecated packages
dotnet list package --deprecated

# Check for outdated packages
dotnet list package --outdated

# Verify .NET SDK/Runtime version is supported LTS
dotnet --version
```

**Detection Patterns (Grep):**

```
# Legacy packages.config (should be migrated to PackageReference)
packages\.config

# Pinned to unsupported .NET versions
<TargetFramework>net5\.0|<TargetFramework>netcoreapp2\.|<TargetFramework>netcoreapp3\.0\b

# Known-vulnerable packages (examples)
<PackageReference Include="log4net" Version="2\.0\.[0-9]\b"
<PackageReference Include="System\.Text\.Encodings\.Web" Version="[45]\."
```

**Mitigations:**

1. Target only supported .NET LTS versions (currently .NET 8, .NET 9).
2. Run `dotnet list package --vulnerable` in CI and fail on findings.
3. Enable NuGet package signing: `<PackageSignatureRequired>true</PackageSignatureRequired>` in `nuget.config`.
4. Migrate `packages.config` projects to SDK-style `<PackageReference>`.
5. Use Dependabot or GitHub Advanced Security for automated NuGet CVE alerts.

---

### A07:2021 — Identification and Authentication Failures

**Detection Patterns (Grep):**

```
# JWT validation disabled
ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|ValidateLifetime\s*=\s*false|RequireExpirationTime\s*=\s*false

# Missing account lockout
LockoutEnabled|MaxFailedAccessAttempts|DefaultLockoutTimeSpan

# Hardcoded JWT signing keys
new SymmetricSecurityKey\(Encoding.*"[A-Za-z0-9+/=]{16,}"

# Cookie without Secure flag
options\.Cookie\.SecurePolicy\s*=\s*CookieSecurePolicy\.None
```

**Vulnerable Patterns and Secure Alternatives:**

**1. Weak JWT validation**

```csharp
// VULNERABLE — issuer and audience not validated; token can be forged by any issuer
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("my-secret-key"))
        };
    });
```

```csharp
// SECURE — full validation with key from configuration
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
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Convert.FromBase64String(builder.Configuration["Jwt:SigningKey"]!))
        };
    });
```

**2. Missing account lockout**

```csharp
// VULNERABLE — no lockout configured
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>();
```

```csharp
// SECURE — lockout enabled with reasonable thresholds
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();
```

**3. Session fixation — not regenerating session on authentication**

```csharp
// SECURE — clear and regenerate session on login
[HttpPost("login")]
public async Task<IActionResult> Login(LoginRequest request)
{
    var result = await _signInManager.PasswordSignInAsync(
        request.Email, request.Password, isPersistent: false, lockoutOnFailure: true);

    if (result.Succeeded)
    {
        // Regenerate session to prevent fixation
        HttpContext.Session.Clear();
        await HttpContext.Session.CommitAsync();
        // ASP.NET Core Identity issues a new auth cookie automatically
        return Ok();
    }
    return Unauthorized();
}
```

---

### A08:2021 — Software and Data Integrity Failures

**Detection Patterns (Grep):**

```
# BANNED deserializers (all are unsafe-by-design)
BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter

# Dangerous Newtonsoft.Json TypeNameHandling
TypeNameHandling\.(All|Auto|Objects|Arrays)

# Unsafe DataContractSerializer with untrusted types
DataContractSerializer.*typeof\(object\)

# Missing SubResource Integrity in views
<script src=.*https://(?!.*integrity)
```

**Vulnerable Patterns and Secure Alternatives:**

**1. Unsafe deserialization with `BinaryFormatter`**

```csharp
// VULNERABLE — BinaryFormatter is BANNED in .NET 8+ (throws at runtime)
// In earlier versions it enables arbitrary code execution
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream); // remote code execution vector
```

```csharp
// SECURE — use System.Text.Json (default in modern .NET)
var obj = await JsonSerializer.DeserializeAsync<MyDto>(stream);

// Or MessagePack / protobuf-net for binary formats:
var obj = MessagePackSerializer.Deserialize<MyDto>(stream);
```

**2. Newtonsoft.Json `TypeNameHandling.All`**

```csharp
// VULNERABLE — allows attacker-controlled type instantiation
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All
};
var obj = JsonConvert.DeserializeObject(json, settings);
```

```csharp
// SECURE — avoid TypeNameHandling entirely, or use a binder
// Best: use System.Text.Json which has no TypeNameHandling equivalent
var obj = System.Text.Json.JsonSerializer.Deserialize<MyDto>(json);

// If Newtonsoft.Json is required:
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.None // default and safe
};
```

**3. Missing NuGet package signing enforcement**

```xml
<!-- SECURE — require signed NuGet packages in nuget.config -->
<configuration>
  <config>
    <add key="signatureValidationMode" value="require" />
  </config>
</configuration>
```

---

### A09:2021 — Security Logging and Monitoring Failures

**Detection Patterns (Grep):**

```
# Check for auth event logging (should be present)
ILogger.*Login|ILogger.*Logout|ILogger.*Authentication|ILogger.*Authorized

# Sensitive data in logs
_logger\.(Log|Information|Warning|Error|Debug).*password|_logger.*token|_logger.*secret|_logger.*creditCard

# Missing structured logging
Console\.WriteLine.*Exception|Console\.Write.*error
```

**Vulnerable Patterns and Secure Alternatives:**

**1. Missing logging for authentication events**

```csharp
// VULNERABLE — no audit trail for auth events
[HttpPost("login")]
public async Task<IActionResult> Login(LoginRequest request)
{
    var result = await _signInManager.PasswordSignInAsync(
        request.Email, request.Password, false, true);
    return result.Succeeded ? Ok() : Unauthorized();
}
```

```csharp
// SECURE — log auth events with structured data (no sensitive values)
[HttpPost("login")]
public async Task<IActionResult> Login(LoginRequest request)
{
    var result = await _signInManager.PasswordSignInAsync(
        request.Email, request.Password, false, true);

    if (result.Succeeded)
    {
        _logger.LogInformation("User {Email} logged in successfully from {IP}",
            request.Email, HttpContext.Connection.RemoteIpAddress);
        return Ok();
    }

    if (result.IsLockedOut)
    {
        _logger.LogWarning("User {Email} account locked out. IP: {IP}",
            request.Email, HttpContext.Connection.RemoteIpAddress);
        return StatusCode(429);
    }

    _logger.LogWarning("Failed login attempt for {Email} from {IP}",
        request.Email, HttpContext.Connection.RemoteIpAddress);
    return Unauthorized();
}
```

**2. Sensitive data in logs**

```csharp
// VULNERABLE — password and token logged
_logger.LogInformation("User login: {Email}, Password: {Password}", email, password);
_logger.LogDebug("Token issued: {Token}", jwtToken);
```

```csharp
// SECURE — never log credentials, tokens, PII
_logger.LogInformation("User login attempted: {Email}", email);
_logger.LogDebug("Token issued for user {UserId}, expires {Expiry}", userId, expiry);
```

---

### A10:2021 — Server-Side Request Forgery (SSRF)

**Detection Patterns (Grep):**

```
# User-controlled URL in HTTP requests
HttpClient.*GetAsync\(.*Request|HttpClient.*PostAsync\(.*Request
new HttpRequestMessage\(.*Request

# Legacy HTTP classes with user-controlled URLs
WebClient.*Download.*Request
HttpWebRequest\.Create\(.*Request

# URL from user input without validation
new Uri\(.*Request|Uri\.TryCreate\(.*Request
```

**Vulnerable Patterns and Secure Alternatives:**

**1. `HttpClient` with user-supplied URL**

```csharp
// VULNERABLE — user can make server fetch internal resources (cloud metadata, etc.)
[HttpGet("fetch")]
public async Task<IActionResult> Fetch([FromQuery] string url)
{
    using var client = new HttpClient();
    var response = await client.GetStringAsync(url);
    return Ok(response);
}
```

```csharp
// SECURE — validate URL scheme, host, and deny internal ranges
[HttpGet("fetch")]
public async Task<IActionResult> Fetch(
    [FromQuery] string url,
    [FromServices] IHttpClientFactory httpClientFactory)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        return BadRequest("Invalid URL");

    // Allow only HTTPS
    if (uri.Scheme != "https")
        return BadRequest("Only HTTPS URLs are allowed");

    // Block internal/private IP ranges
    var host = await Dns.GetHostAddressesAsync(uri.Host);
    foreach (var ip in host)
    {
        if (IsPrivateOrReserved(ip))
            return BadRequest("Internal addresses are not allowed");
    }

    // Allowlist approach (preferred)
    var allowedHosts = new[] { "api.example.com", "cdn.example.com" };
    if (!allowedHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
        return BadRequest("Host not in allowlist");

    var client = httpClientFactory.CreateClient("external");
    var response = await client.GetStringAsync(uri);
    return Ok(response);
}

private static bool IsPrivateOrReserved(IPAddress ip)
{
    byte[] bytes = ip.GetAddressBytes();
    return ip.IsIPv6LinkLocal
        || ip.IsIPv6SiteLocal
        || IPAddress.IsLoopback(ip)
        || (bytes[0] == 10)                                          // 10.0.0.0/8
        || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)    // 172.16.0.0/12
        || (bytes[0] == 192 && bytes[1] == 168)                     // 192.168.0.0/16
        || (bytes[0] == 169 && bytes[1] == 254);                    // 169.254.0.0/16 (link-local / cloud metadata)
}
```

---

## ASP.NET Core Security Configuration Template

Complete `Program.cs` with security best practices for .NET 8+:

```csharp
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// --- Authentication ---
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
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Convert.FromBase64String(builder.Configuration["Jwt:SigningKey"]!))
        };
    });

builder.Services.AddAuthorization();

// --- CORS with explicit origins ---
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()!)
              .AllowCredentials()
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Content-Type", "Authorization");
    });
});

// --- Rate Limiting (.NET 7+) ---
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddFixedWindowLimiter("general", config =>
    {
        config.PermitLimit = 100;
        config.Window = TimeSpan.FromMinutes(1);
        config.QueueLimit = 0;
    });

    options.AddFixedWindowLimiter("auth", config =>
    {
        config.PermitLimit = 5;
        config.Window = TimeSpan.FromMinutes(1);
        config.QueueLimit = 0;
    });
});

// --- Anti-forgery (for Razor/MVC) ---
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// --- Cookie policy ---
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Strict;
    options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
    options.Secure = CookieSecurePolicy.Always;
});

// --- Kestrel hardening ---
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false; // remove Server header
    options.ConfigureHttpsDefaults(https =>
    {
        https.SslProtocols = System.Security.Authentication.SslProtocols.Tls12
                           | System.Security.Authentication.SslProtocols.Tls13;
    });
});

builder.Services.AddControllers();

var app = builder.Build();

// --- Middleware pipeline (ORDER MATTERS) ---

// 1. Exception handling (first — catches everything downstream)
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts(); // HTTP Strict Transport Security
}

// 2. HTTPS redirection
app.UseHttpsRedirection();

// 3. Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none';");
    await next();
});

// 4. Cookie policy
app.UseCookiePolicy();

// 5. CORS
app.UseCors();

// 6. Rate limiting
app.UseRateLimiter();

// 7. Routing
app.UseRouting();

// 8. Authentication (must be before Authorization)
app.UseAuthentication();

// 9. Authorization
app.UseAuthorization();

// 10. Anti-forgery (.NET 8+ — for minimal APIs and Razor)
app.UseAntiforgery();

// 11. Endpoints
app.MapControllers();

app.Run();
```

---

## .NET-Specific Consolidated Grep Detection Patterns

Quick-reference list for automated scanning:

```
# --- A01: Broken Access Control ---
\[ApiController\](?!.*\[Authorize\])
\.AddCors.*AllowAnyOrigin
\[AllowAnonymous\]
Path\.Combine.*Request

# --- A02: Cryptographic Failures ---
MD5\.Create|SHA1\.Create|MD5CryptoServiceProvider|SHA1Managed
new Random\(|System\.Random
RijndaelManaged|DESCryptoServiceProvider|TripleDESCryptoServiceProvider
SslProtocols\.Tls\b|SslProtocols\.Tls11|SslProtocols\.Ssl

# --- A03: Injection ---
FromSqlRaw\(.*\$"|FromSqlRaw\(.*\+
ExecuteSqlRaw\(.*\$"|ExecuteSqlRaw\(.*\+
SqlCommand\(.*\$"|SqlCommand\(.*\+
Process\.Start\(.*\$"|ProcessStartInfo\(.*\$"
DirectorySearcher.*\$"
Html\.Raw\(
MarkupString
DtdProcessing\.Parse|XmlResolver\s*=\s*new

# --- A05: Security Misconfiguration ---
UseDeveloperExceptionPage
UseSwagger\(\)|UseSwaggerUI\(\)
RequiredLength\s*=\s*[1-5]\b
AddServerHeader\s*=\s*true

# --- A07: Authentication Failures ---
ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|ValidateLifetime\s*=\s*false
LockoutEnabled\s*=\s*false

# --- A08: Data Integrity ---
BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter
TypeNameHandling\.(All|Auto|Objects|Arrays)

# --- A09: Logging Failures ---
_logger.*password|_logger.*token|_logger.*secret
Console\.WriteLine.*Exception

# --- A10: SSRF ---
HttpClient.*GetAsync\(.*Request|HttpClient.*PostAsync\(.*Request
WebClient.*Download.*Request
new Uri\(.*Request
```

---

## References

- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [Microsoft ASP.NET Core Security Documentation](https://learn.microsoft.com/en-us/aspnet/core/security/)
- [Microsoft .NET Security Best Practices](https://learn.microsoft.com/en-us/dotnet/standard/security/)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Microsoft Secure Coding Guidelines for .NET](https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines)
