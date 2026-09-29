# Extended Detection Patterns — Tenant-Aware Cache Key Review

This reference provides concrete vulnerable and remediated code patterns across popular languages, frameworks, and caching systems.

---

## 1. Node.js & TypeScript (Express, Fastify, NestJS)

### Vulnerable: Redis Cache Key Missing Tenant ID
```typescript
// Omission of tenant context in key construction
async function getAccountSummary(req: Request, res: Response) {
  const accountId = req.params.accountId;
  const cacheKey = `account:${accountId}:summary`;

  const cached = await redisClient.get(cacheKey);
  if (cached) return res.json(JSON.parse(cached));

  const data = await db.accounts.findFirst({ where: { id: accountId, tenantId: req.user.tenantId } });
  await redisClient.setEx(cacheKey, 300, JSON.stringify(data));
  return res.json(data);
}
```

### Remediated: Explicit Tenant and Role Scoping
```typescript
async function getAccountSummary(req: Request, res: Response) {
  const { tenantId, role } = req.user;
  const accountId = req.params.accountId;

  // Namespace strictly binds tenant, resource, and role
  const cacheKey = `tenant:${tenantId}:account:${accountId}:role:${role}:summary`;
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Vary', 'Authorization, Cookie, X-Tenant-ID');

  const cached = await redisClient.get(cacheKey);
  if (cached) return res.json(JSON.parse(cached));

  const data = await db.accounts.findFirst({ where: { id: accountId, tenantId } });
  if (!data) return res.status(404).json({ error: 'Not found' });

  await redisClient.setEx(cacheKey, 300, JSON.stringify(data));
  return res.json(data);
}
```

---

## 2. Python (FastAPI, Django, Flask)

### Vulnerable: Django / redis-py Key Constructor
```python
# Vulnerable: Key built only from entity ID
def get_project_dashboard(request, project_id: str):
    cache_key = f"dashboard:{project_id}"
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

    project = Project.objects.get(id=project_id, tenant=request.user.tenant)
    cache.set(cache_key, project.to_dict(), timeout=600)
    return JsonResponse(project.to_dict())
```

### Remediated: Scoped Key with Policy Version
```python
def get_project_dashboard(request, project_id: str):
    tenant_id = request.user.tenant_id
    role = request.user.role
    policy_version = get_tenant_policy_version(tenant_id)

    # Scoped key incorporating tenant, role, and policy invalidation version
    cache_key = f"t:{tenant_id}:v:{policy_version}:proj:{project_id}:role:{role}:dash"

    cached_data = cache.get(cache_key)
    if cached_data:
        response = JsonResponse(cached_data)
        response["Cache-Control"] = "private, no-store"
        return response

    project = get_object_or_404(Project, id=project_id, tenant_id=tenant_id)
    payload = project.to_role_filtered_dict(role)
    cache.set(cache_key, payload, timeout=600)

    response = JsonResponse(payload)
    response["Cache-Control"] = "private, no-store"
    return response
```

---

## 3. GraphQL (Apollo Server / DataLoader)

### Vulnerable: Singleton DataLoader Across Requests
```javascript
// DANGEROUS: Process-wide DataLoader retains records across requests and tenants
const globalUserLoader = new DataLoader(async (userIds) => {
  return await db.users.findMany({ where: { id: { in: userIds } } });
});

const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Passing global singleton into context
  context: () => ({ userLoader: globalUserLoader })
});
```

### Remediated: Request-Scoped DataLoader with Tenant Isolation
```javascript
// Safe: New DataLoader instantiated per incoming request with tenant context
const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => {
    const tenantId = req.user.tenantId;
    return {
      user: req.user,
      userLoader: new DataLoader(async (userIds) => {
        // Enforce tenant boundary directly in batch loading query
        return await db.users.findMany({
          where: {
            id: { in: userIds },
            tenantId: tenantId
          }
        });
      })
    };
  }
});
```

---

## 4. Go (Gin, Echo, Chi)

### Vulnerable: Cache Lookup Before Authorization Check
```go
// Vulnerable: Cache hit returns prior tenant's response without checking auth
func GetDocumentHandler(c *gin.Context) {
    docID := c.Param("docId")
    cacheKey := fmt.Sprintf("doc:%s", docID)

    if val, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
        c.Data(http.StatusOK, "application/json", []byte(val))
        return
    }

    tenantID := c.GetString("tenant_id")
    doc, err := db.FindDocument(tenantID, docID)
    // ...
}
```

### Remediated: Tenant-Prefixed Cache Key with Explicit Context
```go
func GetDocumentHandler(c *gin.Context) {
    tenantID := c.GetString("tenant_id")
    role := c.GetString("user_role")
    docID := c.Param("docId")

    cacheKey := fmt.Sprintf("tenant:%s:doc:%s:role:%s", tenantID, docID, role)
    c.Header("Cache-Control", "private, no-store")
    c.Header("Vary", "Authorization, Cookie, X-Tenant-ID")

    if val, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
        c.Data(http.StatusOK, "application/json", []byte(val))
        return
    }

    doc, err := db.FindDocument(tenantID, docID)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
        return
    }

    rdb.Set(ctx, cacheKey, doc.JSON(), 5*time.Minute)
    c.Data(http.StatusOK, "application/json", doc.JSON())
}
```

---

## 5. Edge & CDN Caching (Cloudflare, CloudFront, Fastly)

### Vulnerable: Caching Authenticated Responses Globally
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600
Set-Cookie: session_id=abc123xyz

{"tenant_id": "tenant-a", "api_token": "secret-xyz"}
```
*Risk:* Shared edge CDN stores the response and serves `tenant-a` data to any client requesting the same URL path.

### Remediated: Private Cache Headers
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: private, no-cache, no-store, must-revalidate
Vary: Authorization, Cookie, X-Tenant-ID
Pragma: no-cache
Expires: 0
```
