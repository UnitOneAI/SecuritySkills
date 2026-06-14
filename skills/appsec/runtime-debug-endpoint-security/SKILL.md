---
name: runtime-debug-endpoint-security
description: >
  Detects debug and diagnostics endpoints that persist into production with broader trust than intended, especially during incident handling or rollout pressure. Auto-invoked when reviewing web backend code, internal diagnostics, or administrative interfaces for trust boundary bypasses.
tags: [appsec, debug-endpoint, trust-boundary, diagnostics, production-security]
role: [appsec-engineer, security-engineer]
phase: [build, review, operate]
frameworks: [OWASP-ASVS-4.0.3, CWE, NIST-SP-800-53]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: mkcash
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Runtime Debug Endpoint Security — Trust Boundary Review

A structured, repeatable process for detecting debug and diagnostics endpoints that persist into production with broader trust than intended. This skill maps trust boundaries, identifies where authority is derived, then reviews validation, provenance, exception handling, replay behavior, and background or operator paths that may get broader reach than intended.

---

## 1. When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when:

- **Web backend review** — Reviewing REST/GraphQL/gRPC endpoints, especially admin, debug, or diagnostic routes.
- **Internal diagnostics audit** — Auditing /debug, /health, /metrics, /actuator, /admin, /ops, /internal, or similar paths.
- **Incident response tooling** — Reviewing temporary endpoints added during incident handling that may not have been removed.
- **Feature flag / rollout endpoints** — Endpoints used for gradual rollout or canary analysis that infer trust from weak signals.
- **Operator / background job paths** — Cron jobs, queue workers, or operator tools that reuse request context without fresh authorization.

---

## 2. What to Detect

What signals tell the agent this issue is present? Be precise — give patterns the agent can match, not just descriptions.

| Signal | Pattern | Confidence |
|---|---|---|
| **Route pattern** | Routes matching `/debug*`, `/health*`, `/actuator*`, `/admin*`, `/internal*`, `/ops*`, `/metrics*`, `/diagnostics*`, `/dev*`, `/test*` | HIGH |
| **Missing auth** | Endpoint handler lacks `@PreAuthorize`, `@RequiresAuthentication`, `requireAuth()`, or equivalent middleware | HIGH |
| **Weak trust signal** | Authority derived from `X-Forwarded-For`, `User-Agent`, request IP, header presence, or feature flag without re-check | HIGH |
| **Context reuse** | Request context (user, roles, permissions) reused in background job / async task without fresh authorization | MEDIUM |
| **Exception bypass** | Error handlers / fallback paths that skip auth middleware (e.g., global exception handler returns debug info) | MEDIUM |
| **Replay vulnerability** | Debug endpoint accepts replayed requests without nonce / timestamp validation | MEDIUM |
| **Provenance missing** | Privileged action logged without actor identity, request ID, or approval trail | LOW |
| **Feature flag trust** | Feature flag check used as sole authorization for sensitive operation | MEDIUM |

> For extended detection patterns across languages/frameworks, see [patterns.md](patterns.md).

---

## 3. Rules (Constraints)

Hard rules only — falsifiable and enforceable. No "consider" / "may" language.

- **MUST** map every finding to a real control ID from a `frameworks` entry (OWASP ASVS, CWE, or NIST SP 800-53).
- **MUST NOT** emit a control ID that doesn't resolve in the cited framework.
- **MUST** flag any endpoint matching route patterns in §2 that lacks explicit authorization middleware.
- **MUST** flag any endpoint where authority is derived from a weak context signal (IP, header, feature flag) without a fresh authorization check at the sensitive boundary.
- **MUST** flag any background/async path that reuses request context without fresh authorization.
- **MUST NOT** flag endpoints that are explicitly public by design (e.g., `/health` liveness probe returning only "OK" with no sensitive data).
- **MUST** verify that debug endpoints are either removed, gated behind environment-specific configuration, or protected by strong authentication + authorization in production.

---

## 4. Remediation

What the agent emits or changes when this fires. Keep complex logic in a reference/script file (§7), not inline.

### Before (vulnerable) — Spring Boot Actuator exposed without auth

```java
@GetMapping("/actuator/env")
public Map<String, Object> getEnv() {
    return environment.getSystemEnvironment(); // Exposes all env vars including secrets
}
```

### After (remediated) — Actuator secured with role-based access

```java
@GetMapping("/actuator/env")
@PreAuthorize("hasRole('ADMIN')")
public Map<String, Object> getEnv() {
    return environment.getSystemEnvironment();
}
```

### Before (vulnerable) — Express.js debug endpoint trusts X-Forwarded-For

```javascript
app.get('/debug/request', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    if (clientIp === '127.0.0.1') { // Weak trust signal
        return res.json({ session: req.session, headers: req.headers });
    }
    res.status(403).send('Forbidden');
});
```

### After (remediated) — Explicit auth + no trust inference

```javascript
app.get('/debug/request', requireAuth, requireRole('ADMIN'), (req, res) => {
    return res.json({ 
        session: sanitizeSession(req.session), 
        headers: sanitizeHeaders(req.headers) 
    });
});
```

### Before (vulnerable) — Python FastAPI background task reuses request user

```python
@router.post("/admin/trigger-job")
async def trigger_job(background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user)):
    background_tasks.add_task(run_sensitive_job, current_user.id)  # Reuses user without fresh check
    return {"status": "queued"}

async def run_sensitive_job(user_id: int):
    # Uses user_id without re-verifying permissions
    await sensitive_operation(user_id)
```

### After (remediated) — Fresh authorization in background task

```python
@router.post("/admin/trigger-job")
async def trigger_job(background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user)):
    # Verify permission at request time
    if not await authorize(current_user, "admin:trigger_job"):
        raise HTTPException(403, "Insufficient permissions")
    
    # Pass only job parameters, not user context
    background_tasks.add_task(run_sensitive_job, job_id=generate_job_id(), requested_by=current_user.id)
    return {"status": "queued"}

async def run_sensitive_job(job_id: str, requested_by: int):
    # Re-verify authorization at execution time
    requester = await get_user(requested_by)
    if not await authorize(requester, "admin:trigger_job"):
        logger.warning(f"Job {job_id} blocked: requester lost permissions")
        return
    await sensitive_operation(job_id)
```

---

## 5. Verification (falsifiable)

The skill is not "done" until this passes — binary, not aspirational.

| | |
|---|---|
| **Input** | Minimal vulnerable case: an endpoint matching `/debug*` or `/actuator*` pattern with no authorization middleware, returning sensitive data (session, env vars, config) |
| **Expected output** | Finding with: OWASP ASVS control ID (e.g., V4.2.1), CWE (e.g., CWE-285), location, evidence snippet, remediation example |
| **Pass condition** | Finding emitted with correct control mapping and actionable remediation |
| **Fail condition** | No finding emitted, or finding lacks control ID, or remediation is generic ("add auth") without code example |

Step-by-step confirmation the fix held:
1. Re-scan the modified file with the §2 route patterns.
2. Confirm no matches for unprotected debug/diagnostic endpoints.
3. Confirm intended behavior is unchanged (legitimate health checks still work).

---

## 6. Gotchas (self-improvement loop)

Minimum 2 false positives + 1 precision trap on creation; add more after each run.

### False positives

- **Pattern:** `/health` or `/ready` liveness/readiness probes returning only `{"status": "ok"}` — **Why:** Legitimate infrastructure endpoints, no sensitive data — **Suppress:** Check response body for sensitive fields (session, env, config, user data) before flagging.
- **Pattern:** `/metrics` endpoint exposing only Prometheus-format metrics (no PII, no config) — **Why:** Standard observability, often intentionally public — **Suppress:** Verify metrics don't leak sensitive labels (user IDs, API keys, internal IPs).
- **Pattern:** Feature flag endpoint `/features` returning only flag names/booleans for UI rendering — **Why:** May be needed by frontend — **Suppress:** Check if flags control sensitive operations; if only UI toggles, lower severity.
- **Pattern:** Development-only routes guarded by `if (env === 'development')` — **Why:** Not present in production build — **Suppress:** Verify the guard is at build-time (tree-shaken) not runtime.

### Precision traps

- **Trap:** Remediation adds `@PreAuthorize` but the role hierarchy is misconfigured, granting access to unintended users — **Mitigation:** Verify role definitions and test with least-privilege accounts.
- **Trap:** Moving auth check to background task breaks idempotency or causes duplicate execution — **Mitigation:** Use job IDs with idempotency keys; ensure background task is safely retryable.
- **Trap:** Sanitizing response removes fields needed by legitimate monitoring/alerting — **Mitigation:** Provide separate `/health` (public) and `/actuator/health` (authenticated) endpoints with different detail levels.

### Do NOT flag

- Kubernetes liveness/readiness probes (`/healthz`, `/ready`) returning minimal status.
- Prometheus `/metrics` with standard, non-sensitive metrics.
- Static asset serving routes (`/static/*`, `/assets/*`).
- Explicitly documented public API endpoints with proper auth design.

---

## 7. References (progressive disclosure)

Keep this `SKILL.md` lean. When guidance exceeds ~500 lines, split detail into sibling files in this directory and link them — the agent loads them on demand:

```
skills/appsec/runtime-debug-endpoint-security/
├── SKILL.md                 ← this file (lean entrypoint)
├── patterns.md              ← full detection-pattern library
└── frameworks.md            ← framework-specific guidance
```

- [patterns.md](patterns.md) — extended detection patterns across languages/frameworks
- [frameworks.md](frameworks.md) — Spring Boot, Express.js, FastAPI, Go, .NET specific rules

---

## Submission checklist (delete before submitting)

- [x] Directory is `skills/appsec/runtime-debug-endpoint-security/`; entrypoint is `SKILL.md`
- [x] Frontmatter complete; `name` matches the directory
- [x] Every framework ID is real and resolves (OWASP ASVS V4.2.1, CWE-285, CWE-200, NIST AC-6)
- [x] At least one machine-matchable detection signal (regex / structural)
- [x] Rules are hard constraints (no "consider"/"may")
- [x] Before/after remediation example present (Java, JavaScript, Python)
- [x] Falsifiable verification test defined (binary pass/fail)
- [x] Gotchas: ≥2 false positives + ≥1 precision trap
- [x] `SKILL.md` stays lean; long detail moved to reference files
- [x] `injection-hardened: true` only after reviewing the body against OWASP LLM01:2025
- [x] Commit message: `feat(skill): runtime-debug-endpoint-security — detect debug endpoints with weak trust boundaries`

---

*SecuritySkills Skill Template v2 — UnitOne.ai · matches the format all shipped skills use.*