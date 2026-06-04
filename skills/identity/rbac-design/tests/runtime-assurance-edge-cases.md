# RBAC Runtime Assurance Edge Cases

These fixtures exercise Step 5A runtime authorization assurance. They are intentionally small so reviewers can validate whether the skill distinguishes vulnerable fail-open behavior from approved fail-closed and break-glass patterns.

---

## Fixture 1: Vulnerable Fail-Open PDP and Stale Permit Cache

### Scenario

A finance approvals API uses centralized RBAC/ABAC authorization through a PDP. The API checks whether the caller has the `finance-approver` role for the target tenant before approving payments over USD 10,000.

### Evidence

- When the PDP request times out after 300 ms, the PEP returns `permit` so payment approval can continue.
- If the PDP returns `indeterminate`, the PEP treats the result as `permit` and records only a generic `authz_error=true` field.
- The service caches `finance-approver` permits for 24 hours by user ID and tenant ID.
- Cache entries are not re-keyed by policy version.
- Transfers from Finance to Support remove the role in the IdP, but no revocation event invalidates the service cache.
- Incident containment playbooks disable accounts in the IdP only; they do not purge service-level authorization caches.
- There is no revocation-latency test proving that access stops within an SLA after role removal.
- Decision logs omit policy version, decision reason, enforcement point, and cache hit/miss state.

### Expected Findings

- `RBAC-RUNTIME-02`: The PEP permits when PDP evaluation times out.
- `RBAC-RUNTIME-05`: Decision logs omit policy version, reason, enforcement point, and cache hit/miss state.
- `RBAC-CACHE-02`: Role transfer and incident containment do not invalidate cached permits.
- `RBAC-CACHE-03`: A 24-hour permit TTL exceeds risk tolerance for financial approvals.
- `RBAC-CACHE-04`: Policy version changes do not flush or re-key cached decisions.
- `RBAC-TEST-02`: No revocation-latency test proves access stops within the stated SLA.

---

## Fixture 2: Benign Fail-Closed PDP and Controlled JIT Break-Glass

### Scenario

A tenant administration console protects emergency support actions with centralized PDP checks and a separate just-in-time break-glass flow.

### Evidence

- PDP timeout, network failure, policy exception, `deny`, and `indeterminate` all deny by default.
- The approved degraded mode allows read-only status checks during a PDP outage; write actions remain denied.
- Role and attribute caches use a five-minute TTL for support workflows and are invalidated on role removal, tenant transfer, incident containment, and policy version change.
- Cache keys include subject ID, tenant ID, action, resource type, and policy version.
- Break-glass activation requires an incident ticket, MFA, two approvers, and an explicit reason.
- Break-glass grants expire after 30 minutes, are session recorded, alert the security channel, and are revoked automatically when the incident closes.
- CI includes allow, deny, negative authorization, revocation-latency, and decision-diff tests before policy rollout.
- Decision logs include subject, resource, action, policy version, decision, reason, enforcement point, correlation ID, and cache hit/miss state.

### Expected Findings

- No `RBAC-RUNTIME-01` or `RBAC-RUNTIME-02` finding: deny, indeterminate, timeout, network failure, and policy exception do not permit.
- No `RBAC-CACHE-01` finding: caches have explicit TTLs.
- No `RBAC-CACHE-02` finding: revocation, transfer, incident containment, and policy version changes invalidate cached permits.
- No `RBAC-TEST-01`, `RBAC-TEST-02`, or `RBAC-TEST-03` finding: the policy-test pipeline includes allow/deny, revocation-latency, and decision-diff coverage.
- Break-glass access should be calibrated by activation, expiry, recording, alerting, and revocation evidence rather than treated as a wildcard-role finding by itself.
