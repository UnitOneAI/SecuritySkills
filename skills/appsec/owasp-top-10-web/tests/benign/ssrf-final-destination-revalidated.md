---
name: ssrf-final-destination-revalidated
expected: benign
category: A10:2021
cwe: CWE-918
---

# Benign SSRF Fixture: Redirects Disabled and Destination Revalidated

This fixture should not be flagged as SSRF when reviewing the URL-fetching
path. The code validates the URL before the request, disables automatic
redirect following, and resolves every address for the effective destination
immediately before sending the request.

```csharp
[HttpGet("preview")]
public async Task<IActionResult> Preview(
    [FromQuery] string url,
    [FromServices] IHttpClientFactory httpClientFactory)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
    {
        return BadRequest("invalid URL");
    }

    if (!IsAllowedDestination(uri))
    {
        return BadRequest("destination not allowed");
    }

    var client = httpClientFactory.CreateClient("no-redirects");
    using var response = await client.GetAsync(uri);

    if ((int)response.StatusCode is >= 300 and < 400)
    {
        return BadRequest("redirects are not followed for previews");
    }

    return Content(await response.Content.ReadAsStringAsync(), "text/html");
}

private static bool IsAllowedDestination(Uri uri)
{
    if (uri.Scheme != Uri.UriSchemeHttps)
    {
        return false;
    }

    if (!AllowedHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
    {
        return false;
    }

    foreach (var address in Dns.GetHostAddresses(uri.Host))
    {
        if (IsPrivateOrReserved(address))
        {
            return false;
        }
    }

    return true;
}
```

## Expected Safe Evidence

| Evidence Gate | Fixture State |
|---------------|---------------|
| Initial scheme and host allowlist | Present on the request path |
| DNS and IP range validation | Present before request send |
| Redirect final-destination validation | Automatic redirects disabled |
| Time-of-use validation | Validation happens inside the request handler |

The skill should accept this as compensating evidence instead of reporting a
finding based only on the presence of `GetAsync(uri)`.
