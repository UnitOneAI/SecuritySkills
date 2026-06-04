---
name: ssrf-redirect-final-destination
expected: vulnerable
category: A10:2021
cwe: CWE-918
---

# Vulnerable SSRF Fixture: Initial URL Validated, Redirect Destination Trusted

This fixture should be flagged as SSRF. The route validates the original URL
scheme and hostname, but it then allows the HTTP client to follow redirects
automatically. A permitted public host can redirect the server to a cloud
metadata endpoint or another private address.

```csharp
[HttpGet("preview")]
public async Task<IActionResult> Preview([FromQuery] string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
    {
        return BadRequest("invalid URL");
    }

    if (uri.Scheme != "https" || !AllowedHosts.Contains(uri.Host))
    {
        return BadRequest("destination not allowed");
    }

    using var handler = new HttpClientHandler
    {
        AllowAutoRedirect = true
    };
    using var client = new HttpClient(handler);

    var html = await client.GetStringAsync(uri);
    return Content(html, "text/html");
}
```

## Expected Finding Evidence

| Evidence Gate | Fixture State |
|---------------|---------------|
| Initial scheme and host allowlist | Present |
| Redirect final-destination validation | Missing |
| Resolved IP range check after redirect | Missing |
| Egress control evidence | Missing |

The skill should report that the effective request destination is not
constrained even though the initial URL string has an allowlist check.
