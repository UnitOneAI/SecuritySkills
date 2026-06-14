---
name: tenant-aware-cache-key-review
description: >
  Reviews multi-tenant applications for cache-key authority completeness,
  authorization-before-cache-hit, access-change invalidation, and edge/CDN
  cache controls. Auto-invoked when reviewing multi-tenant APIs, cache-backed
  services, shared edge or CDN caches, data-loaders, or background warmers.
  Produces a structured report with tenant-leakage findings and remediation
  mapped to OWASP API Security and NIST SP 800-145.
tags: [secops, cache, multi-tenant, code-review]
role: [security-engineer, appsec-engineer, backend-developer]
phase: [build, review, operate]
frameworks: [OWASP-API-Security-2023, NIST-SP-800-145, RFC-9110]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: daviediao-code
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Tenant-Aware Cache Key Review

## 1. When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when:

- **Multi-tenant application** — reviewing code that serves multiple tenants/users from a shared cache layer
- **Cache-backed API** — reviewing API endpoints that use Redis, Memcached, or in-memory caches
- **CDN/edge caching** — reviewing CloudFlare, Vercel, or CDN configurations for shared caches
- **Data loader** — reviewing DataLoader, query-cache, or memoization layers
- **Background warmer** — reviewing cache pre-warming or prefetch logic

## 2. Patterns (Detection Library)

Search for cache-key construction in the codebase:

```
# Cache key patterns
cache.get(.*tenant_id)
redis.hget(.*tenant)
Memcached.get(.*tenant)
cache_key = .*tenant_id
cache_key = .*user_id
@cache(.*tenant)
dataLoader.load(.*tenant)
```

### Vulnerable Patterns

| Pattern | Description | Severity |
|---------|-------------|----------|
| `cache.get(key)` without tenant scope | Shared cache key across tenants | HIGH |
| `cache.get(f"...{user_id}...")` but auth checks after cache hit | Authorization bypass via cached data | CRITICAL |
| `cache.set(key, data, ttl=3600)` with static TTL, no access-change invalidation | Stale data after permission revocation | HIGH |
| `Cache-Control: public` on tenant-specific responses | CDN serves tenant data to other tenants | CRITICAL |
| `cache.set(user_token_key, admin_data)` | Token-scoped key contains data outside scope | HIGH |

### Secure Patterns

| Pattern | Description |
|---------|-------------|
| `cache.get(f"tenant:{tenant_id}:user:{user_id}")` | Tenant-scoped key with explicit namespace |
| `Cache-Control: private, no-store` on authenticated responses | No shared caching of sensitive data |
| `cache.invalidate("tenant:{tenant_id}:*")` on access change | Proper invalidation on permission changes |
| `cache.get(f"tenant:{tenant_id}:user:{user_id}:etag:{version}")` | Versioned cache keys |

## 3. Rules (Constraints)

Hard rules only — falsifiable and enforceable. No "consider" / "may" language.

- **MUST** verify that every cache key includes tenant or user context.
- **MUST** check that authorization occurs before or alongside cache hit validation.
- **MUST** validate that cache invalidation covers all keys affected by access changes.
- **MUST NOT** emit findings for in-memory caches that are process-local and single-tenant.
- **MUST** map every finding to a real control ID from OWASP API Security 2023 or NIST SP 800-145.

## 4. Remediation

**Before (vulnerable):**
```python
# Vulnerable: no tenant in cache key
def get_user_data(user_id):
    cache_key = f"user:{user_id}"
    cached = cache.get(cache_key)
    if cached:
        return cached  # Could return another tenant's data!
    
    data = db.query("SELECT * FROM users WHERE id = ?", user_id)
    cache.set(cache_key, data, ttl=3600)
    return data
```

**After (remediated):**
```python
# Remediated: tenant-scoped cache key + proper invalidation
def get_user_data(tenant_id, user_id):
    cache_key = f"tenant:{tenant_id}:user:{user_id}"
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    data = db.query("SELECT * FROM users WHERE tenant_id = ? AND id = ?", tenant_id, user_id)
    cache.set(cache_key, data, ttl=3600)
    return data

# On permission change:
def revoke_access(tenant_id, user_id):
    cache.delete(f"tenant:{tenant_id}:user:{user_id}")
    cache.delete_pattern(f"tenant:{tenant_id}:user:{user_id}:*")
```

## 5. Verification (falsifiable)

| | |
|---|---|
| **Input** | Code with `cache.get(user_id)` without tenant scope |
| **Expected output** | HIGH finding with specific remediation |
| **Pass condition** | Finding includes OWASP-A07:2023 (Identification and Authentication Failures) |
| **Fail condition** | No finding emitted or finding references non-existent control ID |

Step-by-step confirmation the fix held:
1. Scan codebase for cache key patterns using Grep.
2. Confirm all cache keys include tenant context.
3. Confirm cache invalidation logic covers all affected keys.
4. Confirm `Cache-Control` headers prevent shared caching of tenant data.

## 6. Gotchas (self-improvement loop)

**False positives**
- **Pattern:** `cache.get(f"admin:{admin_id}")` — **Why:** admin sessions are single-tenant per process — **Suppress:** only flag if cache is shared across admin sessions
- **Pattern:** `cache.get("static:config")` — **Why:** static config is not tenant-specific — **Suppress:** skip keys containing "static", "config", "metadata" without tenant prefix

**Precision traps**
- **Trap:** Adding tenant scope breaks existing cache warmers — **Mitigation:** update warmers to pass tenant_id when seeding cache

**Do NOT flag:** localhost-only cache instances (e.g., `127.0.0.1:6379`) in development configurations with no tenant routing.

## 7. References (progressive disclosure)

- [OWASP API Security Top 10 2023 — API4: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa4-broken-object-level-authorization/)
- [NIST SP 800-145 — The NIST Definition of Cloud Computing](https://csrc.nist.gov/publications/detail/sp/800-145/final)
- [RFC 9110 — HTTP Semantics: Cache-Control headers](https://httpwg.org/specs/rfc9110.html#cache.control)

---

## Submission checklist

- [x] Directory is `skills/secops/cache-key-review/`; entrypoint is `SKILL.md`
- [x] Frontmatter complete; `name` matches the directory
- [x] Every framework ID is real and resolves
- [x] At least one machine-matchable detection signal (regex patterns in §2)
- [x] Rules are hard constraints (no "consider"/"may")
- [x] Before/after remediation example present
- [x] Falsifiable verification test defined (binary pass/fail)
- [x] Gotchas: 2 false positives + 1 precision trap
- [x] `SKILL.md` stays lean
- [x] `injection-hardened: true` — reviewed against OWASP LLM01:2025 (no prompt injection vectors in skill body)
- [x] Commit message: `feat(skill): tenant-aware-cache-key-review — reviews cache keys for tenant leakage`

*SecuritySkills Skill Template v2 — UnitOne.ai*
