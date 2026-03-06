# OWASP API Security Top 10:2023 -- Detailed Checklist

This file contains the detailed OWASP API Top 10 checklist items with vulnerable patterns, remediation guidance, and review checklists for the API Security Review skill. See [SKILL.md](SKILL.md) for the main skill definition, process overview, and output format.

---

## API1:2023 -- Broken Object Level Authorization (BOLA)

**CWE:** CWE-285 (Improper Authorization), CWE-639 (Authorization Bypass Through User-Controlled Key)
**Severity:** Critical to High

BOLA occurs when an API endpoint accepts an object identifier from the client and does not verify that the authenticated user is authorized to access the specific object. This is the most prevalent and critical API vulnerability.

### What to Look For

- Endpoints that accept resource IDs in the URL path, query parameters, or request body.
- Authorization logic that checks only whether the user is authenticated, not whether they own or have access to the specific object.
- Sequential or predictable resource identifiers (auto-increment integers) that enable enumeration.
- Batch or list endpoints that return objects without filtering by the caller's permissions.

### REST Vulnerable Patterns

```python
# VULNERABLE: No ownership check -- any authenticated user can access any order
@app.route('/api/v1/orders/<order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    order = db.orders.find_one({"_id": order_id})
    return jsonify(order)
```

Remediation:

```python
# SECURE: Verify the authenticated user owns the requested resource
@app.route('/api/v1/orders/<order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    order = db.orders.find_one({"_id": order_id, "user_id": current_user.id})
    if not order:
        return jsonify({"error": "Not found"}), 404
    return jsonify(order)
```

### GraphQL Vulnerable Patterns

```graphql
# VULNERABLE: Any authenticated user can query any user's private data
type Query {
  user(id: ID!): User
  order(id: ID!): Order
}
```

```javascript
// VULNERABLE: Resolver fetches object without ownership validation
const resolvers = {
  Query: {
    order: async (_, { id }, context) => {
      return await Order.findById(id);  // No authorization check
    },
  },
};
```

Remediation:

```javascript
// SECURE: Resolver enforces ownership before returning data
const resolvers = {
  Query: {
    order: async (_, { id }, context) => {
      const order = await Order.findById(id);
      if (!order || order.userId !== context.user.id) {
        throw new ForbiddenError("Not authorized");
      }
      return order;
    },
  },
};
```

### BOLA vs BFLA Distinction

BOLA and BFLA (API5:2023) are frequently confused. The distinction is critical for accurate findings:

| Aspect | BOLA (API1) | BFLA (API5) |
|--------|-------------|-------------|
| **What is bypassed** | Object-level access (horizontal) | Function-level access (vertical) |
| **Attack vector** | Manipulate resource identifier to access another user's object | Call an endpoint intended for a different role or privilege level |
| **Example** | Regular user accesses `GET /api/orders/9999` belonging to another user | Regular user calls `DELETE /api/admin/users/42` intended for admins |
| **Authorization gap** | Missing ownership/relationship check on the data object | Missing role/permission check on the operation itself |
| **CWE** | CWE-639 (User-Controlled Key) | CWE-285 (Improper Authorization) |

Both can coexist in a single endpoint. An endpoint may lack both a role check (BFLA) and an ownership check (BOLA).

### Review Checklist

- [ ] Every endpoint that accepts a resource identifier enforces ownership or relationship-based access control.
- [ ] Authorization checks happen at the data access layer, not only at the controller/route layer.
- [ ] Batch/list endpoints filter results by the caller's permissions.
- [ ] Resource identifiers are UUIDs or non-sequential values to resist enumeration.
- [ ] GraphQL resolvers enforce authorization on every field that returns sensitive data.

---

## API2:2023 -- Broken Authentication

**CWE:** CWE-287 (Improper Authentication), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-798 (Use of Hard-coded Credentials)
**Severity:** Critical to High

APIs are particularly susceptible to authentication flaws because they expose machine-consumable endpoints that lack the browser-based protections (cookies, CSRF tokens, CAPTCHA) common in traditional web applications.

### What to Look For

- Authentication endpoints without brute-force protection (rate limiting, account lockout, CAPTCHA).
- JWT validation that is missing or incomplete -- no signature verification, no expiration check, acceptance of the `none` algorithm.
- API keys transmitted in URL query strings (logged in server access logs, browser history, proxies).
- Missing or weak token rotation -- refresh tokens that never expire or are not rotated on use.
- Password reset or account recovery flows that leak tokens or allow enumeration.
- Micro-service-to-service communication without authentication (implicit trust based on network location).

### Vulnerable Patterns

```python
# VULNERABLE: JWT signature not verified
import jwt
token_data = jwt.decode(token, options={"verify_signature": False})
```

```javascript
// VULNERABLE: No rate limiting on authentication endpoint
app.post('/api/v1/auth/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    return res.json({ token: generateJWT(user) });
  }
  return res.status(401).json({ error: "Invalid credentials" });
});
```

```yaml
# VULNERABLE: API key in query parameter (logged in access logs)
paths:
  /api/v1/data:
    get:
      parameters:
        - name: api_key
          in: query  # Should be in header
```

### Remediation Guidance

- Enforce rate limiting on all authentication endpoints (e.g., 5 attempts per minute per IP/account).
- Validate JWT signatures using a strong algorithm (RS256, ES256). Reject `none` and `HS256` if RSA is expected (algorithm confusion attack).
- Transmit API keys and tokens in HTTP headers (`Authorization` header), never in URL query strings.
- Implement token expiration: access tokens (5-15 minutes), refresh tokens (hours to days with rotation).
- Use `bcrypt`, `scrypt`, or `Argon2id` for password storage.
- Authenticate service-to-service calls with mTLS or signed tokens, not network-based trust.

### Review Checklist

- [ ] All authentication endpoints have brute-force protections (rate limiting, lockout).
- [ ] JWTs are validated for signature, expiration (`exp`), issuer (`iss`), and audience (`aud`).
- [ ] The `none` algorithm and algorithm confusion attacks are prevented by explicit algorithm allowlisting.
- [ ] API keys and tokens are transmitted in headers, not query strings.
- [ ] Refresh tokens are rotated on each use and revocable.
- [ ] Service-to-service communication is explicitly authenticated.

---

## API3:2023 -- Broken Object Property Level Authorization

**CWE:** CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
**Severity:** High to Medium

This risk covers two related problems: excessive data exposure (the API returns more object properties than the client needs, including sensitive fields) and mass assignment (the API accepts and processes more properties than it should, allowing clients to modify fields they should not control).

### Vulnerable Patterns

```python
# VULNERABLE: Excessive data exposure -- returns all fields including sensitive ones
@app.route('/api/v1/users/<user_id>')
@require_auth
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())  # Includes password_hash, ssn, internal_role
```

```python
# VULNERABLE: Mass assignment -- client can set any field including role
@app.route('/api/v1/users/profile', methods=['PUT'])
@require_auth
def update_profile():
    current_user.update(**request.json)  # Client can send {"role": "admin"}
    db.session.commit()
    return jsonify(current_user.to_dict())
```

```javascript
// VULNERABLE: GraphQL exposes sensitive fields with no restriction
const UserType = new GraphQLObjectType({
  name: 'User',
  fields: {
    id: { type: GraphQLID },
    email: { type: GraphQLString },
    passwordHash: { type: GraphQLString },  // Should never be exposed
    role: { type: GraphQLString },
    ssn: { type: GraphQLString },            // Requires field-level auth
  },
});
```

### Remediation Guidance

- Define explicit response schemas (DTOs/serializers) for every endpoint. Never return raw database objects.
- Use allowlists for writable fields on update/create operations. Never bind request bodies directly to models.
- In GraphQL, implement field-level authorization directives or resolver-level checks for sensitive fields.
- Strip sensitive properties (`password_hash`, `internal_id`, `role`, `ssn`) from all responses unless the endpoint specifically requires them for an authorized consumer.

### Review Checklist

- [ ] Every API response uses a defined schema or serializer that explicitly lists returned fields.
- [ ] Sensitive fields (credentials, PII, internal metadata) are excluded from standard responses.
- [ ] Update endpoints use an allowlist of modifiable fields; mass assignment is impossible.
- [ ] GraphQL fields containing sensitive data have resolver-level authorization.
- [ ] API documentation (OpenAPI spec) accurately reflects the actual response schema.

---

## API4:2023 -- Unrestricted Resource Consumption

**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption), CWE-799 (Improper Control of Interaction Frequency)
**Severity:** High to Medium

### Vulnerable Patterns

```python
# VULNERABLE: No pagination limit -- client can request all records
@app.route('/api/v1/transactions')
@require_auth
def list_transactions():
    limit = request.args.get('limit', type=int)  # No max; client sends limit=1000000
    transactions = Transaction.query.filter_by(user_id=current_user.id).limit(limit).all()
    return jsonify([t.to_dict() for t in transactions])
```

```graphql
# VULNERABLE: GraphQL allows deeply nested queries (denial of service)
query {
  users {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}
```

```javascript
// VULNERABLE: No request body size limit
app.use(express.json()); // Default limit may be very large or unconfigured
```

### Remediation Guidance

- Implement rate limiting at the API gateway and/or application layer. Use sliding window or token bucket algorithms. Set per-endpoint limits based on expected legitimate usage.
- Enforce maximum pagination size (e.g., `limit` capped at 100). Default to a reasonable page size (e.g., 20).
- Set maximum request body sizes (`express.json({ limit: '1mb' })`).
- For GraphQL: enforce query depth limits (e.g., max depth 5), complexity analysis (weighted field costs), and batch query limits.
- Set execution timeouts for database queries and downstream API calls.
- Implement cost alerts and circuit breakers for operations that trigger billable third-party APIs.

### Review Checklist

- [ ] Rate limiting is configured for all endpoints, with stricter limits on expensive operations.
- [ ] Pagination has a maximum page size enforced server-side.
- [ ] Request body size limits are configured.
- [ ] GraphQL queries have depth limits, complexity limits, and batch restrictions.
- [ ] Database queries and downstream calls have execution timeouts.
- [ ] Billable operations have cost controls and alerting.

---

## API5:2023 -- Broken Function Level Authorization (BFLA)

**CWE:** CWE-285 (Improper Authorization)
**Severity:** Critical to High

### Vulnerable Patterns

```python
# VULNERABLE: No role check -- any authenticated user can delete any user
@app.route('/api/v1/admin/users/<user_id>', methods=['DELETE'])
@require_auth  # Checks authentication but not authorization
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return jsonify({"status": "deleted"})
```

```javascript
// VULNERABLE: GraphQL mutation lacks role enforcement
const resolvers = {
  Mutation: {
    setUserRole: async (_, { userId, role }, context) => {
      // Any authenticated user can set roles -- no admin check
      return await User.findByIdAndUpdate(userId, { role });
    },
  },
};
```

### Remediation Guidance

- Implement a centralized authorization middleware or policy engine that enforces role/permission checks consistently across all endpoints.
- Deny by default: every endpoint should require explicit permission grants. Do not rely on "security through obscurity" of admin URL paths.
- Enforce authorization on every HTTP method independently. A user authorized to `GET` a resource is not automatically authorized to `DELETE` it.
- In GraphQL, use directive-based or middleware-based authorization on mutations (`@hasRole(role: ADMIN)`).
- Regularly audit the endpoint inventory against the authorization policy matrix to detect gaps.

### Review Checklist

- [ ] All administrative and privileged endpoints enforce role-based authorization.
- [ ] Authorization middleware is centralized and applied consistently.
- [ ] Each HTTP method on each endpoint has an independent authorization check.
- [ ] GraphQL mutations enforce role/permission checks in resolvers or directives.
- [ ] The authorization policy is deny-by-default; endpoints are inaccessible unless explicitly permitted.

---

## API6:2023 -- Unrestricted Access to Sensitive Business Flows

**CWE:** CWE-799 (Improper Control of Interaction Frequency), CWE-837 (Improper Enforcement of a Single, Unique Action)
**Severity:** High to Medium

### Vulnerable Patterns

```python
# VULNERABLE: No anti-automation on purchase flow
@app.route('/api/v1/tickets/purchase', methods=['POST'])
@require_auth
def purchase_ticket():
    ticket = find_available_ticket(request.json['event_id'])
    if ticket:
        ticket.assign_to(current_user)
        charge_payment(current_user, ticket.price)
        return jsonify({"ticket_id": ticket.id}), 200
    return jsonify({"error": "Sold out"}), 409
```

### Remediation Guidance

- Implement business-level rate limiting based on user identity, not just IP (e.g., max 4 ticket purchases per user per event).
- Add CAPTCHA or proof-of-work challenges on business-critical flows that should be human-initiated.
- Use device fingerprinting and behavioral analysis to detect automated access patterns.
- Implement velocity checks: flag or block accounts that perform business operations at inhuman speed.
- Consider step-up verification (SMS/email confirmation) for high-value operations.

### Review Checklist

- [ ] Business-critical flows have per-user velocity limits appropriate to the business context.
- [ ] Anti-automation controls (CAPTCHA, proof-of-work) are in place on human-initiated flows.
- [ ] Device fingerprinting or behavioral analysis is used to distinguish human from automated traffic.
- [ ] High-value operations require step-up verification.
- [ ] Business logic abuse scenarios are documented and monitored.

---

## API7:2023 -- Server Side Request Forgery (SSRF)

**CWE:** CWE-918 (Server-Side Request Forgery)
**Severity:** High

### Vulnerable Patterns

```python
# VULNERABLE: Fetches any URL provided by the user
@app.route('/api/v1/preview', methods=['POST'])
@require_auth
def url_preview():
    url = request.json['url']
    response = requests.get(url)  # Attacker sends http://169.254.169.254/latest/meta-data/
    return jsonify({"content": response.text[:500]})
```

```python
# VULNERABLE: Webhook registration accepts any URL
@app.route('/api/v1/webhooks', methods=['POST'])
@require_auth
def register_webhook():
    webhook_url = request.json['url']  # Attacker registers http://internal-service:8080/admin
    Webhook.create(user_id=current_user.id, url=webhook_url)
    return jsonify({"status": "registered"})
```

### Remediation Guidance

- Validate and sanitize all user-supplied URLs. Use an allowlist of permitted schemes (`https` only), domains, or IP ranges.
- Resolve hostnames and reject private/internal IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16` (cloud metadata), `fd00::/8` (IPv6 ULA).
- Disable HTTP redirects or re-validate the destination after following redirects.
- Use a dedicated egress proxy for outbound requests that enforces domain allowlists.
- For cloud environments, use IMDSv2 (requires token-based access to metadata) to mitigate SSRF exploitation against cloud metadata services.
- Do not return raw responses from fetched URLs to the client; extract only the needed data.

### Review Checklist

- [ ] All user-supplied URLs are validated against a scheme and domain allowlist.
- [ ] Resolved IP addresses are checked against private/internal ranges before the request is made.
- [ ] HTTP redirects are disabled or the final destination is re-validated.
- [ ] Cloud metadata endpoint access is restricted (IMDSv2 on AWS, equivalent on GCP/Azure).
- [ ] Raw responses from fetched URLs are never returned directly to the client.

---

## API8:2023 -- Security Misconfiguration

**CWE:** CWE-16 (Configuration), CWE-611 (Improper Restriction of XML External Entity Reference), CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
**Severity:** High to Medium

### Vulnerable Patterns

```python
# VULNERABLE: Overly permissive CORS
from flask_cors import CORS
CORS(app, origins="*", supports_credentials=True)  # Allows any origin with credentials
```

```javascript
// VULNERABLE: Verbose error messages in production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,       // Exposes internal details
    query: err.sql,         // Exposes database queries
  });
});
```

```java
// VULNERABLE: XXE enabled in XML parser
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// No XXE protections configured
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(request.getInputStream());
```

### Remediation Guidance

- Configure CORS with an explicit allowlist of permitted origins. Never use `*` with `credentials: true`.
- Set security response headers on all API responses:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store` on sensitive responses
- Return generic error messages in production. Log detailed errors server-side with correlation IDs.
- Disable unnecessary HTTP methods. Return `405 Method Not Allowed` for unsupported methods.
- Disable XML External Entity processing: set `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- Enforce TLS 1.2+ with strong cipher suites. Disable TLS 1.0 and 1.1.
- Automate configuration scanning in CI/CD to detect drift from security baselines.

### Review Checklist

- [ ] CORS is configured with an explicit origin allowlist; wildcard is not used with credentials.
- [ ] Security headers are present on all API responses.
- [ ] Error responses in production are generic; no stack traces, SQL queries, or internal paths.
- [ ] Only required HTTP methods are enabled per endpoint.
- [ ] TLS 1.2+ is enforced with strong cipher suites.
- [ ] XML parsers disable external entity processing and DTD loading.
- [ ] Default credentials are changed or removed on all infrastructure components.

---

## API9:2023 -- Improper Inventory Management

**CWE:** CWE-1059 (Insufficient Technical Documentation)
**Severity:** Medium

### What to Look For

- Multiple API versions running simultaneously (`/api/v1/`, `/api/v2/`, `/api/v3/`) where older versions lack security patches.
- Debug or test endpoints present in production (`/api/debug/`, `/api/test/`, `/api/internal/`, `/graphql/playground`).
- Undocumented endpoints that exist in code but are absent from the OpenAPI specification.
- API endpoints exposed to the public internet that should be internal-only.
- Deprecated endpoints that remain functional after the announced retirement date.
- Different security configurations between environments (staging allows unauthenticated access, production does not, but staging is publicly accessible).

### Review Procedure

```
1. Extract all route definitions from source code (Grep for route decorators, handler registrations).
2. Compare against the published OpenAPI/Swagger specification.
3. Flag any endpoint present in code but missing from documentation (shadow API).
4. Flag any endpoint marked as deprecated that is still reachable.
5. Check for environment-specific routes (debug, test, internal) that should not exist in production.
6. Verify that older API versions have equivalent security controls to current versions.
```

### Remediation Guidance

- Maintain a single source of truth for the API inventory. Generate OpenAPI specs from code or validate code against specs in CI/CD.
- Retire deprecated API versions on a defined schedule. Redirect old versions to the current version or return `410 Gone`.
- Remove debug, test, and playground endpoints from production builds using build-time flags or environment checks.
- Segment internal APIs from external APIs at the network level (separate API gateways, VPC isolation).
- Scan for shadow APIs by comparing routing tables against documentation on every deploy.

### Review Checklist

- [ ] The API inventory is documented and matches the actual deployed endpoints.
- [ ] Deprecated API versions are retired or have equivalent security controls.
- [ ] No debug, test, or playground endpoints are accessible in production.
- [ ] Internal APIs are not reachable from external networks.
- [ ] CI/CD pipelines validate that code routes match the API specification.

---

## API10:2023 -- Unsafe Consumption of APIs

**CWE:** CWE-20 (Improper Input Validation), CWE-295 (Improper Certificate Validation), CWE-319 (Cleartext Transmission of Sensitive Information)
**Severity:** High to Medium

### Vulnerable Patterns

```python
# VULNERABLE: Third-party API data used in SQL without sanitization
partner_data = requests.get("https://partner-api.example.com/products").json()
for product in partner_data:
    db.execute(f"INSERT INTO products (name) VALUES ('{product['name']}')")
```

```python
# VULNERABLE: TLS certificate verification disabled
response = requests.get("https://third-party-api.com/data", verify=False)
```

```javascript
// VULNERABLE: Upstream API data rendered without escaping
const enrichmentData = await fetch('https://enrichment-api.com/user/' + userId);
const data = await enrichmentData.json();
res.send(`<div class="bio">${data.biography}</div>`);  // Stored XSS via third party
```

### Remediation Guidance

- Treat all data from external and internal APIs as untrusted input. Validate and sanitize before use.
- Always enforce TLS certificate validation on outbound connections. Never set `verify=False` or `rejectUnauthorized: false` in production.
- Validate response schemas from upstream APIs using a schema validator (JSON Schema, Pydantic, Zod).
- Implement timeouts, retry limits with backoff, and circuit breakers on all outbound API calls.
- Restrict redirects on outbound calls. If following redirects, re-validate the destination URL.
- Use parameterized queries when inserting data from any source, including trusted internal APIs.

### Review Checklist

- [ ] Data from all upstream APIs is validated and sanitized before use in queries, rendering, or commands.
- [ ] TLS certificate validation is enabled on all outbound API calls.
- [ ] Response schemas from third-party APIs are validated before processing.
- [ ] Outbound calls have timeouts, retry limits, and circuit breakers.
- [ ] Redirect following is disabled or restricted on outbound HTTP calls.
