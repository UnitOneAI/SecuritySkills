# Reviewer Checklist — Tenant-Aware Cache Key Review

Use this checklist during code reviews, threat modeling, or automated security scans to verify that caching layers maintain strict tenant boundary isolation.

---

## 1. Authority & Key Construction
- [ ] **Server-derived tenant ID:** Is the tenant identifier extracted exclusively from validated session/token claims, never from untrusted query parameters or headers?
- [ ] **Hierarchical prefixing:** Does the cache key follow a structured namespace scheme (e.g. `tenant:<tenantId>:<entityType>:<entityId>`)?
- [ ] **Role & entitlement scoping:** If the cached payload varies depending on the actor's role, permissions, or license tier, are those dimensions embedded in the key?
- [ ] **Delimiter safety:** Are key components separated by unambiguous delimiters that prevent cross-field collision (e.g. avoiding raw string concatenation)?

## 2. Authorization Timing & Verification
- [ ] **Pre-cache authorization:** Is the caller's tenant membership and object access verified before checking the cache, OR is the cached entity re-authorized before return?
- [ ] **Property filtering:** Are sensitive or administrative fields filtered according to the current caller's permissions, even on a cache hit?
- [ ] **Negative caching boundaries:** If 404 or "not found" results are cached, are they scoped to the tenant to prevent cross-tenant resource enumeration?

## 3. Invalidation & Lifecycle Management
- [ ] **Membership revocation:** When a user is removed from a tenant, are their cached sessions and scoped responses invalidated immediately?
- [ ] **Role changes:** When an actor is downgraded, are cached administrative views invalidated or superseded by a policy version bump?
- [ ] **Tenant deletion/suspension:** Does deleting or suspending a tenant purge or permanently invalidate all associated cache namespaces?
- [ ] **Cross-tenant purge safety:** Can a cache purge or eviction operation initiated by one tenant ever impact another tenant's keys?

## 4. Shared Proxies & Edge Caching
- [ ] **Private response headers:** Do authenticated API responses return `Cache-Control: private, no-store`?
- [ ] **Vary header completeness:** Does the `Vary` header include `Authorization`, `Cookie`, and custom tenant headers when edge caching is active?
- [ ] **DataLoader lifecycle:** In GraphQL services, are DataLoader instances scoped strictly to individual requests rather than process singletons?
- [ ] **Background warmers:** Do asynchronous cache pre-warmers strictly segment data generation by tenant context?
