# C# and .NET -- Secure Code Review Patterns

A language-specific supplement for the `secure-code-review` skill, covering C# on .NET 6+, ASP.NET Core, Entity Framework Core, and Blazor. This file provides vulnerable-and-remediated code pairs, grep-ready detection patterns, and a configuration checklist aligned to the parent skill's review steps, OWASP ASVS 4.0.3 controls, and CWE identifiers.

---

## Vulnerable Patterns by Review Step

### Input Validation and Injection (Step 2)

#### 1. SQL Injection (CWE-89)

**ASVS Control:** V5.3.4

**EF Core -- `FromSqlRaw` with string interpolation**

```csharp
// VULNERABLE: user input interpolated into raw SQL
public async Task<List<Product>> SearchProducts(string name)
{
    return await _context.Products
        .FromSqlRaw("SELECT * FROM Products WHERE Name = '" + name + "'")
        .ToListAsync();
}
```

Remediation: Use `FromSqlInterpolated` (which parameterizes automatically) or pass explicit parameters to `FromSqlRaw`.

```csharp
// SECURE: parameterized via FromSqlInterpolated
public async Task<List<Product>> SearchProducts(string name)
{
    return await _context.Products
        .FromSqlInterpolated($"SELECT * FROM Products WHERE Name = {name}")
        .ToListAsync();
}
```

**ADO.NET -- `SqlCommand` with string concatenation**

```csharp
// VULNERABLE: string concatenation in command text
public SqlDataReader GetUser(string username)
{
    var cmd = new SqlCommand(
        "SELECT * FROM Users WHERE Username = '" + username + "'", _conn);
    return cmd.ExecuteReader();
}
```

Remediation: Use `SqlParameter` objects.

```csharp
// SECURE: parameterized query with SqlParameter
public SqlDataReader GetUser(string username)
{
    var cmd = new SqlCommand(
        "SELECT * FROM Users WHERE Username = @username", _conn);
    cmd.Parameters.AddWithValue("@username", username);
    return cmd.ExecuteReader();
}
```

---

#### 2. Cross-Site Scripting -- XSS (CWE-79)

**ASVS Control:** V5.2.1, V5.3.1

**Razor -- `Html.Raw()` with user input**

```csharp
// VULNERABLE: Html.Raw disables Razor's automatic HTML encoding
<p>Welcome, @Html.Raw(Model.DisplayName)</p>
```

Remediation: Remove `Html.Raw` and let Razor auto-encode, or sanitize with a library such as HtmlSanitizer before rendering.

```csharp
// SECURE: Razor auto-encodes by default
<p>Welcome, @Model.DisplayName</p>
```

**Blazor -- `MarkupString` with untrusted data**

```csharp
// VULNERABLE: MarkupString renders raw HTML from user input
@((MarkupString)userProvidedHtml)
```

Remediation: Sanitize the HTML before wrapping it in `MarkupString`. Use the Ganss.Xss.HtmlSanitizer NuGet package or equivalent.

```csharp
// SECURE: sanitize before rendering
@{
    var sanitizer = new HtmlSanitizer();
    var safeHtml = sanitizer.Sanitize(userProvidedHtml);
}
@((MarkupString)safeHtml)
```

---

#### 3. OS Command Injection (CWE-78)

**ASVS Control:** V5.3.8

```csharp
// VULNERABLE: user input passed directly to Process.Start with shell
public string RunDiagnostic(string host)
{
    var psi = new ProcessStartInfo("cmd.exe", "/c ping " + host)
    {
        RedirectStandardOutput = true,
        UseShellExecute = false
    };
    var process = Process.Start(psi);
    return process.StandardOutput.ReadToEnd();
}
```

Remediation: Avoid shell invocations. Pass arguments as a separate parameter and validate against an allowlist.

```csharp
// SECURE: no shell, argument isolated, input validated
public string RunDiagnostic(string host)
{
    if (!Regex.IsMatch(host, @"^[a-zA-Z0-9.\-]+$"))
        throw new ArgumentException("Invalid hostname.");

    var psi = new ProcessStartInfo("ping", host)
    {
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };
    var process = Process.Start(psi);
    return process.StandardOutput.ReadToEnd();
}
```

---

#### 4. Path Traversal (CWE-22)

**ASVS Control:** V12.3.2

```csharp
// VULNERABLE: Path.Combine does not prevent traversal sequences
public IActionResult DownloadFile(string filename)
{
    var path = Path.Combine(_uploadDir, filename);
    return PhysicalFile(path, "application/octet-stream");
}
```

Remediation: Resolve the full path and verify it stays within the allowed base directory.

```csharp
// SECURE: canonicalize and validate the resolved path
public IActionResult DownloadFile(string filename)
{
    var basePath = Path.GetFullPath(_uploadDir);
    var fullPath = Path.GetFullPath(Path.Combine(_uploadDir, filename));

    if (!fullPath.StartsWith(basePath + Path.DirectorySeparatorChar))
        return BadRequest("Invalid file path.");

    if (!System.IO.File.Exists(fullPath))
        return NotFound();

    return PhysicalFile(fullPath, "application/octet-stream");
}
```

---

#### 5. LDAP Injection (CWE-90)

**ASVS Control:** V5.3.7

```csharp
// VULNERABLE: unescaped user input in LDAP filter
public SearchResult FindUser(string username)
{
    var searcher = new DirectorySearcher(_directoryEntry)
    {
        Filter = "(uid=" + username + ")"
    };
    return searcher.FindOne();
}
```

Remediation: Escape special LDAP characters in filter values.

```csharp
// SECURE: escape LDAP special characters before building filter
public static string LdapEscape(string input)
{
    return input
        .Replace("\\", "\\5c").Replace("*", "\\2a")
        .Replace("(", "\\28").Replace(")", "\\29")
        .Replace("\0", "\\00");
}

public SearchResult FindUser(string username)
{
    var searcher = new DirectorySearcher(_directoryEntry)
    {
        Filter = "(uid=" + LdapEscape(username) + ")"
    };
    return searcher.FindOne();
}
```

---

#### 6. XML External Entity -- XXE (CWE-611)

**ASVS Control:** V5.5.1

```csharp
// VULNERABLE: XmlDocument with DTD processing enabled (default in older .NET)
public XmlDocument ParseXml(Stream input)
{
    var doc = new XmlDocument();
    doc.XmlResolver = new XmlUrlResolver(); // enables external entity resolution
    doc.Load(input);
    return doc;
}
```

Remediation: Disable DTD processing and set `XmlResolver` to null.

```csharp
// SECURE: DTD processing disabled, no external entity resolution
public XmlDocument ParseXml(Stream input)
{
    var doc = new XmlDocument();
    doc.XmlResolver = null;
    var settings = new XmlReaderSettings
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null
    };
    using var reader = XmlReader.Create(input, settings);
    doc.Load(reader);
    return doc;
}
```

---

#### 7. Regular Expression Denial of Service -- ReDoS (CWE-1333)

**ASVS Control:** V5.1.3

```csharp
// VULNERABLE: unbounded regex on user input with catastrophic backtracking
public bool ValidateInput(string input)
{
    return Regex.IsMatch(input, @"^(a+)+$");
}
```

Remediation: Set a timeout on the `Regex` instance and simplify the pattern.

```csharp
// SECURE: timeout prevents catastrophic backtracking
public bool ValidateInput(string input)
{
    var regex = new Regex(@"^a+$", RegexOptions.None, TimeSpan.FromSeconds(1));
    return regex.IsMatch(input);
}
```

---

### Authentication and Session (Step 3)

#### 1. Hard-coded Credentials (CWE-798)

**ASVS Control:** V2.10.1

```csharp
// VULNERABLE: connection string with credentials in appsettings.json or source
{
    "ConnectionStrings": {
        "DefaultConnection": "Server=db.internal;Database=app;User Id=sa;Password=P@ssw0rd!;"
    }
}
```

Remediation: Use Azure Key Vault, AWS Secrets Manager, environment variables, or the .NET Secret Manager for development. Never commit credentials to source control.

```csharp
// SECURE: load secrets from environment or a secrets manager
builder.Configuration.AddEnvironmentVariables();
// Or in development:
// builder.Configuration.AddUserSecrets<Program>();
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
```

---

#### 2. Weak Session / Cookie Configuration

**ASVS Control:** V3.4.1, V3.4.2, V3.4.3

```csharp
// VULNERABLE: insecure cookie settings
builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = false;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
});
```

Remediation: Set `HttpOnly`, `Secure`, and `SameSite` on all session and authentication cookies.

```csharp
// SECURE: hardened cookie settings
builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.IdleTimeout = TimeSpan.FromMinutes(20);
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
});
```

---

#### 3. Missing Authentication (CWE-306)

**ASVS Control:** V2.1.1

```csharp
// VULNERABLE: sensitive controller action with no [Authorize] attribute
[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        await _userService.DeleteAsync(id);
        return NoContent();
    }
}
```

Remediation: Apply `[Authorize]` at the controller or action level and use policy-based authorization for role constraints.

```csharp
// SECURE: authentication and role-based authorization enforced
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        await _userService.DeleteAsync(id);
        return NoContent();
    }
}
```

---

#### 4. Insecure JWT Validation

**ASVS Control:** V3.1.1

```csharp
// VULNERABLE: critical validation checks disabled
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = false
        };
    });
```

Remediation: Enable all validation checks with correct expected values.

```csharp
// SECURE: full JWT validation enabled
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
            ClockSkew = TimeSpan.FromMinutes(1),
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
        };
    });
```

---

### Authorization (Step 4)

#### 1. Missing Authorization (CWE-862)

**ASVS Control:** V4.1.1

```csharp
// VULNERABLE: API controller with no authorization -- any caller can access
[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> GetOrder(int id)
    {
        var order = await _orderRepo.GetByIdAsync(id);
        return Ok(order);
    }
}
```

Remediation: Apply `[Authorize]` and verify resource ownership.

```csharp
// SECURE: authorization required, ownership verified
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class OrdersController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> GetOrder(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var order = await _orderRepo.GetByIdAsync(id);
        if (order is null) return NotFound();
        if (order.UserId != userId) return Forbid();
        return Ok(order);
    }
}
```

---

#### 2. Insecure Direct Object Reference -- IDOR

**ASVS Control:** V4.2.1

```csharp
// VULNERABLE: user-supplied ID used without ownership check
[HttpPut("profile/{id}")]
public async Task<IActionResult> UpdateProfile(int id, ProfileDto dto)
{
    var profile = await _db.Profiles.FindAsync(id);
    profile.Bio = dto.Bio;
    await _db.SaveChangesAsync();
    return Ok();
}
```

Remediation: Derive the resource scope from the authenticated user's identity, not from the request.

```csharp
// SECURE: profile ID resolved from authenticated user
[HttpPut("profile")]
[Authorize]
public async Task<IActionResult> UpdateProfile(ProfileDto dto)
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var profile = await _db.Profiles.FirstOrDefaultAsync(p => p.UserId == userId);
    if (profile is null) return NotFound();
    profile.Bio = dto.Bio;
    await _db.SaveChangesAsync();
    return Ok();
}
```

---

#### 3. Cross-Site Request Forgery -- CSRF (CWE-352)

**ASVS Control:** V4.2.2

**MVC -- missing anti-forgery token**

```csharp
// VULNERABLE: POST action without anti-forgery validation
[HttpPost]
public IActionResult TransferFunds(TransferModel model)
{
    _bankService.Transfer(model.FromAccount, model.ToAccount, model.Amount);
    return RedirectToAction("Confirmation");
}
```

Remediation: Apply `[ValidateAntiForgeryToken]` on state-changing actions or enable auto-validation globally.

```csharp
// SECURE: anti-forgery token validated
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult TransferFunds(TransferModel model)
{
    _bankService.Transfer(model.FromAccount, model.ToAccount, model.Amount);
    return RedirectToAction("Confirmation");
}
```

For API controllers using JWT or token-based auth, CSRF tokens may not be required if cookies are not used for authentication. Document the reasoning.

---

#### 4. Mass Assignment / Over-Posting (CWE-915)

**ASVS Control:** V4.1.2

```csharp
// VULNERABLE: binding directly to domain entity -- attacker can set IsAdmin
[HttpPost("register")]
public async Task<IActionResult> Register(User user)
{
    _db.Users.Add(user);
    await _db.SaveChangesAsync();
    return Ok();
}
```

Remediation: Use a DTO or the `[Bind]` attribute to restrict which properties can be set from the request.

```csharp
// SECURE: DTO limits which fields the client can set
public record RegisterDto(string Username, string Email, string Password);

[HttpPost("register")]
public async Task<IActionResult> Register(RegisterDto dto)
{
    var user = new User
    {
        Username = dto.Username,
        Email = dto.Email,
        PasswordHash = _hasher.HashPassword(null, dto.Password),
        IsAdmin = false // explicitly set, not client-controlled
    };
    _db.Users.Add(user);
    await _db.SaveChangesAsync();
    return Ok();
}
```

---

### Cryptography (Step 5)

#### 1. Weak Algorithms

**ASVS Control:** V6.2.2, V6.2.5

```csharp
// VULNERABLE: MD5, SHA1, DES, and RijndaelManaged in ECB mode are broken
var md5Hash = MD5.Create().ComputeHash(data);
var sha1Hash = SHA1.Create().ComputeHash(data);
var des = DESCryptoServiceProvider.Create();
var rijndael = new RijndaelManaged { Mode = CipherMode.ECB };
```

Remediation: Use SHA-256/SHA-512 for hashing, AES-GCM for symmetric encryption.

```csharp
// SECURE: SHA-256 for integrity, AES-GCM for encryption
var sha256Hash = SHA256.HashData(data);

using var aesGcm = new AesGcm(key, tagSizeInBytes: 16);
var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
RandomNumberGenerator.Fill(nonce);
var ciphertext = new byte[plaintext.Length];
var tag = new byte[16];
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
```

---

#### 2. Insecure Randomness

**ASVS Control:** V6.3.1

```csharp
// VULNERABLE: System.Random is not cryptographically secure
var random = new Random();
var token = random.Next().ToString("x8");
```

Remediation: Use `RandomNumberGenerator` for all security-sensitive random values.

```csharp
// SECURE: cryptographically secure random token
var tokenBytes = RandomNumberGenerator.GetBytes(32);
var token = Convert.ToBase64String(tokenBytes);
```

---

#### 3. Hard-coded Encryption Keys

**ASVS Control:** V6.4.1

```csharp
// VULNERABLE: encryption key embedded in source code
private static readonly byte[] Key =
    Encoding.UTF8.GetBytes("MyS3cretEncrypt!");
```

Remediation: Use the ASP.NET Core Data Protection API or load keys from a key management service.

```csharp
// SECURE: Data Protection API manages key lifecycle
builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(blobUri)
    .ProtectKeysWithAzureKeyVault(keyVaultKeyUri, credential);

// Usage:
public class TokenService
{
    private readonly IDataProtector _protector;
    public TokenService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("Tokens.V1");
    }
    public string Protect(string plaintext) => _protector.Protect(plaintext);
    public string Unprotect(string encrypted) => _protector.Unprotect(encrypted);
}
```

---

#### 4. Weak Password Hashing

**ASVS Control:** V2.1.1

```csharp
// VULNERABLE: raw SHA-256 for password storage -- fast, no salt
public string HashPassword(string password)
{
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
    return Convert.ToHexString(bytes);
}
```

Remediation: Use ASP.NET Core Identity's `PasswordHasher<T>` (PBKDF2 with 100,000+ iterations) or a dedicated library for Argon2id.

```csharp
// SECURE: ASP.NET Core Identity password hasher (PBKDF2)
var hasher = new PasswordHasher<ApplicationUser>();
var hash = hasher.HashPassword(user, password);

// Verification:
var result = hasher.VerifyHashedPassword(user, hash, providedPassword);
if (result == PasswordVerificationResult.Failed)
    return Unauthorized();
```

---

### Error Handling and Logging (Step 6)

#### 1. Stack Trace Exposure

**ASVS Control:** V7.4.1

```csharp
// VULNERABLE: developer exception page enabled in production
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseDeveloperExceptionPage(); // copy-paste error -- also in production
}
```

```csharp
// ALSO VULNERABLE: returning exception details in API responses
[HttpGet("{id}")]
public IActionResult GetItem(int id)
{
    try { return Ok(_service.Get(id)); }
    catch (Exception ex)
    {
        return StatusCode(500, new { error = ex.ToString() });
    }
}
```

Remediation: Use `UseExceptionHandler` in production and return only a correlation ID to the client.

```csharp
// SECURE: generic error handler in production
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
}

// Error endpoint returns only a correlation ID
[ApiExplorerSettings(IgnoreApi = true)]
[Route("/error")]
public IActionResult HandleError()
{
    var correlationId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
    _logger.LogError("Unhandled exception. Correlation: {CorrelationId}", correlationId);
    return Problem(detail: $"An internal error occurred. Reference: {correlationId}",
                   statusCode: 500);
}
```

---

#### 2. Sensitive Data in Logs

**ASVS Control:** V7.1.1

```csharp
// VULNERABLE: logging passwords and tokens
_logger.LogInformation("User {User} login with password {Password}", username, password);
_logger.LogDebug("Bearer token: {Token}", accessToken);
```

Remediation: Never log secrets. Log the event and outcome only.

```csharp
// SECURE: log event without sensitive data
_logger.LogInformation("Login attempt for user {User}: {Outcome}", username, success ? "success" : "failure");
```

---

### Deserialization and File Handling (Step 8)

#### 1. Unsafe Deserialization (CWE-502)

**ASVS Control:** V5.5.1

The following serializers are effectively banned in .NET -- they allow arbitrary type instantiation and enable remote code execution:

- `BinaryFormatter`
- `NetDataContractSerializer`
- `ObjectStateFormatter`
- `LosFormatter`
- `SoapFormatter`

```csharp
// VULNERABLE: BinaryFormatter enables arbitrary code execution
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(untrustedStream);
```

Remediation: Use `System.Text.Json` or `JsonSerializer` with explicit type mapping. Never deserialize arbitrary types from untrusted input.

```csharp
// SECURE: System.Text.Json with a known target type
var options = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true,
    // Do not use JsonSerializerOptions with TypeNameHandling-like behavior
};
var obj = await JsonSerializer.DeserializeAsync<OrderDto>(request.Body, options);
```

If using Newtonsoft.Json, never set `TypeNameHandling` to anything other than `None`:

```csharp
// VULNERABLE: Newtonsoft TypeNameHandling enables type instantiation attacks
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All // allows arbitrary type deserialization
};
var obj = JsonConvert.DeserializeObject(json, settings);
```

```csharp
// SECURE: TypeNameHandling.None (the default)
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.None
};
var obj = JsonConvert.DeserializeObject<OrderDto>(json, settings);
```

---

#### 2. Unrestricted File Upload (CWE-434)

**ASVS Control:** V12.1.1, V12.3.1, V12.4.1

```csharp
// VULNERABLE: no file type or size validation on IFormFile
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    var path = Path.Combine("wwwroot/uploads", file.FileName);
    using var stream = System.IO.File.Create(path);
    await file.CopyToAsync(stream);
    return Ok(new { url = "/uploads/" + file.FileName });
}
```

Remediation: Validate file type, enforce size limits, generate a safe filename, and store outside the webroot.

```csharp
// SECURE: validated, renamed, stored outside webroot
private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".jpg", ".jpeg", ".png", ".pdf" };

[HttpPost("upload")]
[RequestSizeLimit(5_000_000)] // 5 MB
public async Task<IActionResult> Upload(IFormFile file)
{
    var ext = Path.GetExtension(file.FileName);
    if (!AllowedExtensions.Contains(ext))
        return BadRequest("File type not allowed.");

    var safeFileName = $"{Guid.NewGuid()}{ext}";
    var storagePath = Path.Combine(_uploadsDir, safeFileName); // outside wwwroot

    using var stream = System.IO.File.Create(storagePath);
    await file.CopyToAsync(stream);
    return Ok(new { fileId = safeFileName });
}
```

---

#### 3. Server-Side Request Forgery -- SSRF (CWE-918)

**ASVS Control:** V12.6.1

```csharp
// VULNERABLE: user-supplied URL fetched without restriction
[HttpGet("proxy")]
public async Task<IActionResult> Proxy([FromQuery] string url)
{
    var response = await _httpClient.GetAsync(url);
    var content = await response.Content.ReadAsStringAsync();
    return Content(content, response.Content.Headers.ContentType?.ToString());
}
```

Remediation: Validate the URL scheme, resolve the hostname, reject private/loopback IPs, and restrict to an allowlist of permitted domains.

```csharp
// SECURE: URL validated against allowlist and private IP ranges blocked
private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    { "api.example.com", "cdn.example.com" };

[HttpGet("proxy")]
public async Task<IActionResult> Proxy([FromQuery] string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        return BadRequest("Invalid URL.");

    if (uri.Scheme != "https")
        return BadRequest("Only HTTPS is allowed.");

    if (!AllowedHosts.Contains(uri.Host))
        return BadRequest("Host not permitted.");

    var addresses = await Dns.GetHostAddressesAsync(uri.Host);
    if (addresses.Any(a => IsPrivateOrLoopback(a)))
        return BadRequest("Internal addresses are not allowed.");

    var response = await _httpClient.GetAsync(uri);
    var content = await response.Content.ReadAsStringAsync();
    return Content(content, response.Content.Headers.ContentType?.ToString());
}

private static bool IsPrivateOrLoopback(IPAddress address)
{
    if (IPAddress.IsLoopback(address)) return true;
    var bytes = address.GetAddressBytes();
    return bytes[0] switch
    {
        10 => true,
        172 => bytes[1] >= 16 && bytes[1] <= 31,
        192 => bytes[1] == 168,
        _ => false
    };
}
```

---

## .NET-Specific Detection Patterns (Grep)

Use these regex patterns to locate potential vulnerabilities in C# source files.

| Vulnerability | Pattern |
|---|---|
| SQL Injection (EF Core) | `FromSqlRaw\s*\(.*[\+\$]` |
| SQL Injection (ADO.NET) | `new SqlCommand\s*\(.*[\+\$]` |
| SQL Injection (string concat) | `(SELECT\|INSERT\|UPDATE\|DELETE).*["']\s*\+` |
| XSS (Razor) | `Html\.Raw\s*\(` |
| XSS (Blazor) | `MarkupString\)` |
| OS Command Injection | `Process\.Start\s*\(.*[\+\$]` |
| Path Traversal | `Path\.Combine\s*\(.*Request` |
| XXE | `XmlResolver\s*=\s*new\s+XmlUrlResolver` |
| XXE (DTD) | `DtdProcessing\s*=\s*DtdProcessing\.Parse` |
| LDAP Injection | `DirectorySearcher.*Filter\s*=.*[\+\$]` |
| ReDoS | `new\s+Regex\s*\([^)]*\)\s*[^,]` (missing timeout parameter) |
| Hard-coded credentials | `(Password\|Secret\|Key)\s*=\s*"[^"]{8,}"` |
| BinaryFormatter | `BinaryFormatter` |
| NetDataContractSerializer | `NetDataContractSerializer` |
| ObjectStateFormatter | `ObjectStateFormatter` |
| LosFormatter | `LosFormatter` |
| SoapFormatter | `SoapFormatter` |
| Newtonsoft TypeNameHandling | `TypeNameHandling\s*=\s*TypeNameHandling\.\s*(All\|Auto\|Objects\|Arrays)` |
| Insecure random | `new\s+Random\s*\(` |
| Weak crypto (MD5) | `MD5\.Create\s*\(` |
| Weak crypto (SHA1) | `SHA1\.Create\s*\(` |
| Weak crypto (DES) | `DESCryptoServiceProvider` |
| ECB mode | `CipherMode\.ECB` |
| Missing Authorize | `\[HttpPost\]` or `\[HttpDelete\]` without preceding `\[Authorize` |
| Developer exception in prod | `UseDeveloperExceptionPage` |
| Insecure cookie | `SecurePolicy\s*=\s*CookieSecurePolicy\.None` |
| JWT validation disabled | `Validate(Issuer\|Audience\|Lifetime\|IssuerSigningKey)\s*=\s*false` |
| Anti-forgery missing | `\[HttpPost\]` without `\[ValidateAntiForgeryToken\]` (MVC only) |
| Sensitive data in logs | `Log(Information\|Debug\|Warning)\s*\(.*([Pp]assword\|[Tt]oken\|[Ss]ecret)` |
| Unrestricted upload | `IFormFile.*CopyToAsync` (inspect for missing validation) |
| SSRF | `HttpClient.*GetAsync\s*\(.*Request` |

---

## ASP.NET Core Security Configuration Checklist

### HTTPS and Transport Security

```csharp
// Enforce HTTPS redirection and HSTS
app.UseHttpsRedirection();
app.UseHsts();

// Configure HSTS options
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
    options.Preload = true;
});
```

### Anti-Forgery Token Configuration

```csharp
// Global anti-forgery for MVC
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

// For Blazor Server or minimal API, configure the anti-forgery service
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});
```

### CORS Policy

```csharp
// Restrict CORS to specific origins -- never use AllowAnyOrigin with AllowCredentials
builder.Services.AddCors(options =>
{
    options.AddPolicy("Production", policy =>
    {
        policy.WithOrigins("https://app.example.com")
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Content-Type", "Authorization")
              .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
    });
});

app.UseCors("Production");
```

### Middleware Ordering

```csharp
// Correct order is security-critical
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors("Production");
app.UseAuthentication();  // must come before UseAuthorization
app.UseAuthorization();
app.UseRateLimiter();
app.MapControllers();
```

### Security Headers

```csharp
// Add security headers via middleware or a NuGet package such as NWebsec
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
    await next();
});
```

### Data Protection API

```csharp
// Configure Data Protection for key management
builder.Services.AddDataProtection()
    .SetApplicationName("MyApplication")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));
    // In production, persist keys to durable storage and protect with a KMS:
    // .PersistKeysToAzureBlobStorage(...)
    // .ProtectKeysWithAzureKeyVault(...)
```

---

## .NET-Specific Tooling

| Tool | Purpose | Command / Integration |
|---|---|---|
| Roslyn Security Guard | Roslyn-based SAST analyzer for C# | Add `SecurityCodeScan.VS2019` NuGet package; findings appear as compiler warnings |
| Semgrep .NET rules | Pattern-matching SAST | `semgrep --config p/csharp` |
| `dotnet list package --vulnerable` | Known-vulnerable NuGet dependencies | `dotnet list package --vulnerable --include-transitive` |
| SonarQube / SonarCloud | Comprehensive SAST with C# support | Integrate via `dotnet-sonarscanner`: `dotnet sonarscanner begin /k:project-key` then `dotnet build` then `dotnet sonarscanner end` |
| `dotnet format analyzers` | Run all configured Roslyn analyzers | `dotnet format analyzers --severity warn` |
| DevSkim | Microsoft security linter | VS Code extension or CLI: `devskim analyze --source-code ./src` |
| NuGet Audit | Built-in audit on restore (.NET 8+) | `dotnet restore` (audit runs automatically; configure in `Directory.Build.props`) |

---

## References

- **OWASP .NET Security Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html
- **Microsoft Secure Coding Guidelines:** https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines
- **ASP.NET Core Security Documentation:** https://learn.microsoft.com/en-us/aspnet/core/security/
- **BinaryFormatter Security Guide:** https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide
- **OWASP ASVS 4.0.3:** https://owasp.org/www-project-application-security-verification-standard/
- **CWE Top 25 (2024):** https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html
