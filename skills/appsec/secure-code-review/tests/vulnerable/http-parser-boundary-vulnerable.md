# Vulnerable Test Cases -- HTTP Parser Boundary and Request Smuggling

These code samples **should** trigger the HTTP parser boundary review gate (Step 2.4) and be classified as CWE-444 or related findings.

---

## 1. Nginx forwarding attacker-controlled Transfer-Encoding

**Expected finding:** CWE-444 -- High severity (proxy/backend desync enabling request smuggling)

```nginx
# nginx.conf
location /api/ {
    proxy_http_version 1.1;
    proxy_set_header Transfer-Encoding $http_transfer_encoding;
    proxy_set_header Host $host;
    proxy_pass http://node_backend;
}
```

**Why it triggers:** The `proxy_set_header Transfer-Encoding $http_transfer_encoding` directive forwards the client-controlled Transfer-Encoding header directly to the backend. An attacker can send a crafted request with conflicting Content-Length and Transfer-Encoding headers. Nginx (HTTP/1.1 parser) and Node.js may interpret the body boundary differently, enabling request smuggling.

**Boundary evidence required:**
- Frontend: Nginx reverse proxy
- Backend: Node.js HTTP server
- Protocol: HTTP/1.1 forwarded
- Header policy: Transfer-Encoding forwarded unmodified
- Conflict handling: None -- no CL/TE normalization
- Route impact: All /api/ routes affected

---

## 2. Express raw-body middleware before framework parser

**Expected finding:** CWE-444 -- Medium severity (body parsing desynchronization)

```javascript
const express = require("express");
const app = express();

// VULNERABLE: raw body consumed globally before framework parser
app.use((req, res, next) => {
  req.raw = [];
  req.on("data", chunk => req.raw.push(chunk));
  next();
});

// Framework parser runs AFTER raw middleware
app.use(express.json());

app.post("/api/data", (req, res) => {
  // req.body may be undefined or empty because the stream was consumed
  res.json({ received: req.body });
});
```

**Why it triggers:** The global middleware consumes the request stream before express.json() can parse it. On routes that expect JSON bodies, the framework parser receives an exhausted stream. Behind a proxy, this desynchronization can interact with request framing to produce parser-boundary ambiguity.

**Boundary evidence required:**
- Frontend: (none or reverse proxy)
- Backend: Express.js with raw middleware
- Raw-body path: Global req.on("data") before framework parser
- Conflict handling: None
- Route impact: All POST routes with body

---

## 3. HTTP/2-to-HTTP/1 downgrade without normalization

**Expected finding:** CWE-444 -- High severity (protocol downgrade desync)

```python
# Backend Python Flask app behind a load balancer that downgrades
# HTTP/2 to HTTP/1.1 without normalizing pseudo-headers
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/submit", methods=["POST"])
def submit():
    # Request may arrive with malformed Content-Length
    # from an HTTP/2 frame converted without validation
    data = request.get_data()
    return f"Received {len(data)} bytes"
```

**Why it triggers:** HTTP/2 uses binary framing and pseudo-headers (:method, :path, :authority). When downgraded to HTTP/1.1, these must be converted to their HTTP/1.1 equivalents. If the load balancer does not normalize during conversion, an attacker can craft HTTP/2 frames with pseudo-header conflicts that desynchronize the backend HTTP/1.1 parser.

---

## 4. Serverless adapter body re-encoding without Content-Length recalculation

**Expected finding:** CWE-444 -- Medium severity (stale framing header)

```javascript
// AWS Lambda handler with API Gateway
// API Gateway base64-encodes the body; adapter decodes but
// does not recalculate Content-Length
exports.handler = async (event) => {
  const body = Buffer.from(
    event.body,
    event.isBase64Encoded ? "base64" : "utf8"
  );
  // Stale Content-Length forwarded to framework
  const proxyReq = {
    method: event.httpMethod,
    path: event.path,
    headers: { ...event.headers },
    body: body,
  };
  return app.handle(proxyReq);
};
```

**Why it triggers:** The API Gateway base64-encodes the body, the adapter decodes it, but the original Content-Length header is forwarded unchanged. If the encoded and decoded body lengths differ, the backend parser sees a Content-Length that does not match actual body bytes, enabling desync.

---

## 5. Duplicate Content-Length headers across proxy layers

**Expected finding:** CWE-444 -- High severity (CL ambiguity)

```
# Attacker sends:
POST /api/transfer HTTP/1.1
Host: target.com
Content-Length: 1
Content-Length: 50
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

```haproxy
# HAProxy configuration (does not reject duplicate CL)
frontend http_front
    bind *:80
    mode http
    default_backend http_back

backend http_back
    mode http
    server s1 10.0.0.1:8080
```

**Why it triggers:** The attacker sends two Content-Length headers (1 and 50). HAProxy may forward both to the backend. The backend parser picks one value, another component picks the other, creating a desynchronization window. If the backend uses CL=1, it sees only the first byte and the rest (GET /admin) is interpreted as a new pipelined request.

---

## 6. Webhook raw-body middleware consumed globally

**Expected finding:** CWE-444 -- Medium severity (global raw-body desync)

```javascript
const express = require("express");
const crypto = require("crypto");
const app = express();

// VULNERABLE: global raw body for webhook signature verification
app.use((req, res, next) => {
  let data = "";
  req.on("data", (chunk) => { data += chunk; });
  req.on("end", () => {
    req.rawBody = data;
    next();
  });
});

app.use(express.json()); // runs AFTER stream consumed

app.post("/webhooks/github", (req, res) => {
  const sig = req.headers["x-hub-signature-256"];
  const expected = "sha256=" + crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("hex");
  if (sig !== expected) return res.status(401).send("Invalid signature");
  res.status(200).send("ok");
});

// Regular API route -- body is gone because raw middleware consumed it
app.post("/api/data", (req, res) => {
  console.log(req.body); // undefined
  res.json({ ok: true });
});
```

**Why it triggers:** The global raw-body middleware consumes the request stream for ALL routes. Behind a proxy, the proxy may have already framed the body based on Content-Length, and the middleware consuming it creates a mismatch between the proxy expectation and what the framework parser sees.
