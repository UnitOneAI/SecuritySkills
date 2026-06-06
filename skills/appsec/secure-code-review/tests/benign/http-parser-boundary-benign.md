# Benign Test Cases -- HTTP Parser Boundary

These code samples should **NOT** be flagged as CWE-444 (request smuggling). They demonstrate safe patterns that must be recognized to avoid false positives.

---

## 1. Go HTTP server with strict parser and bounded limits (no proxy)

**Expected result:** Informational at most -- no CWE-444 finding

```go
// Safe: Go standard library strict parser with bounded limits.
// No reverse proxy in the path, no CL/TE forwarding, no parser disagreement.
srv := &http.Server{
    Addr:              ":8443",
    Handler:           app,
    ReadHeaderTimeout: 5 * time.Second,
    MaxHeaderBytes:    1 << 20,
}
```

**Why this is NOT a finding:** Go's net/http server uses a strict parser that rejects malformed Transfer-Encoding and duplicate Content-Length by default. ReadHeaderTimeout bounds slow-loris attacks. MaxHeaderBytes limits memory consumption. Without a proxy that uses different parsing semantics, there is no parser boundary mismatch. Large header limits alone do not constitute request smuggling risk.

---

## 2. Route-scoped raw body for webhook signature verification

**Expected result:** No CWE-444 finding (raw body is properly scoped)

```javascript
const express = require("express");
const crypto = require("crypto");
const app = express();

// Safe: raw body is scoped to the specific webhook route
app.post("/webhooks/stripe",
  express.raw({ type: "application/json" }),
  (req, res, next) => {
    const sig = req.headers["stripe-signature"];
    const expected = crypto
      .createHmac("sha256", process.env.STRIPE_SECRET)
      .update(req.body)
      .digest("hex");
    if (sig !== expected) return res.status(401).send("Invalid");
    next();
  },
  handleStripeWebhook
);

// Regular JSON route -- body is NOT consumed by raw middleware
app.post("/api/data", express.json(), (req, res) => {
  res.json({ received: req.body }); // works correctly
});
```

**Why this is NOT a finding:** The raw body middleware is applied only to the `/webhooks/stripe` route via route-level middleware. Other routes use `express.json()` independently. There is no global middleware consuming the stream before the framework parser, so no desynchronization occurs.

---

## 3. Nginx with proper hop-by-hop header stripping

**Expected result:** No CWE-444 finding (proxy normalizes correctly)

```nginx
# Safe: strips client-controlled hop-by-hop headers, sets explicit protocol
location /api/ {
    proxy_http_version 1.1;
    proxy_set_header Content-Length "";
    proxy_set_header Transfer-Encoding "";
    proxy_set_header Connection "";
    proxy_pass http://node_backend;
}
```

**Why this is NOT a finding:** The proxy explicitly strips Transfer-Encoding, Content-Length, and Connection headers before forwarding. The backend receives a clean request with the proxy's own framing headers. There is no client-controlled header that could cause parser disagreement.

---

## 4. Well-configured HAProxy with strict header validation

**Expected result:** No CWE-444 finding (proxy rejects malformed requests)

```haproxy
# Safe: rejects duplicate Content-Length, enforces single parser
frontend http_front
    bind *:80
    mode http
    http-request deny deny_status 400 if { hdr_cnt(Content-Length) gt 1 }
    http-request deny deny_status 400 if { hdr_cnt(Transfer-Encoding) gt 1 }
    http-request deny if { req.hdr(Transfer-Encoding) -m len chunked } !{ req.hdr(Content-Length) -m len 0 }
    default_backend http_back

backend http_back
    mode http
    server s1 10.0.0.1:8080
```

**Why this is NOT a finding:** The HAProxy frontend explicitly rejects requests with duplicate Content-Length or Transfer-Encoding headers. CL/TE conflicts are denied at the edge. The backend never receives ambiguous framing headers.

---

## 5. Python Flask behind Cloudflare with standard settings

**Expected result:** No CWE-444 finding (Cloudflare normalizes)

```python
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/data", methods=["POST"])
def handle_data():
    # Cloudflare normalizes headers before forwarding.
    # Standard Cloudflare configuration strips hop-by-hop headers
    # and rejects duplicate Content-Length.
    data = request.get_json()
    return {"received": data}
```

**Why this is NOT a finding:** Cloudflare's reverse proxy normalizes HTTP requests by default: it strips hop-by-hop headers, rejects malformed Transfer-Encoding, and uses a single consistent parser. The Flask application receives a well-formed request. Without evidence that Cloudflare is misconfigured or using a non-standard setup, there is no parser boundary mismatch.
