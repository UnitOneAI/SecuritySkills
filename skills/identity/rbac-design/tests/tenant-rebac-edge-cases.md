# RBAC Design Tenant and ReBAC Edge Case Fixtures

These fixtures validate the issue #36 improvement: the skill must classify the authorization model before applying role metrics, cover ReBAC tuple graphs, and require negative tests for policy conflict and lifecycle edge cases.

## Test Case 1: Tenant-Scoped Single-User Role Is Not Automatically Role Explosion

### Input Scenario

```text
Tenant acme creates role incident-exporter-2026-06.
Assigned users: 1
Permissions: export support-ticket evidence for tenant acme only
Controls: owner recorded, MFA required, reason required, expires in 6 hours
```

### Expected Review Behavior

- Classify the role as tenant/customer RBAC or emergency access before applying workforce role metrics.
- Treat the single-user assignment as an indicator, not an automatic finding.
- Verify tenant scope, owner, privilege level, MFA, reason capture, expiry, and review evidence before deciding severity.

### Failure Mode Caught

Without model classification, the skill can overflag valid tenant-scoped or emergency roles as role explosion.

## Test Case 2: Break-Glass Role Requires Activation Controls

### Input Scenario

```text
Role: production-break-glass
Assigned users: 4
Activation: manual Slack approval described in runbook
No technical expiry, no MFA check in activation path, no post-use review task
```

### Expected Review Behavior

- Classify as emergency / break-glass access.
- Review activation controls rather than only role count.
- Flag missing technical expiry, deterministic MFA enforcement, alerting, and post-use review.

### Failure Mode Caught

Without break-glass-specific checks, the skill can either overfocus on assignment count or understate missing activation controls.

## Test Case 3: ReBAC Cross-Tenant Parent Inheritance

### Input Scenario

```text
document:tenant-a/doc-1 parent folder:tenant-b/root
folder:tenant-b/root viewer group:tenant-b/support
user:tenant-b/alice member group:tenant-b/support
```

### Expected Review Behavior

- Classify the model as ReBAC / tuple graph or hybrid.
- Require a tenant-boundary invariant preventing `document.parent` from crossing tenants unless explicit sharing exists.
- Require a denied-path model test proving tenant B group membership cannot grant access to tenant A documents through a parent tuple.

### Failure Mode Caught

Without ReBAC tuple checks, role and attribute reviews may look correct while inherited tuple paths grant cross-tenant access.

## Test Case 4: Permit/Deny Conflict Must Prove Deny Precedence

### Input Scenario

```rego
allow {
  input.subject.department == input.resource.department
}

deny {
  input.resource.classification == "restricted"
  not input.subject.clearance == "restricted"
}
```

### Expected Review Behavior

- Identify the policy engine and combining algorithm.
- Require a negative test where both `allow` and `deny` match and the final decision is deny.
- Mark the design incomplete if the engine uses "any permit wins" or if conflict resolution is undocumented.

### Failure Mode Caught

Without conflict semantics, the skill can miss broad permits overriding explicit restrictions.

## Test Case 5: Stale Attribute and Offboarding Paths

### Input Scenario

```text
subject.contractor_status is cached for 24 hours.
Access policy denies expired contractors.
HR offboarding event updates the source system immediately.
PDP reads from the cache and has no event-driven invalidation.
```

### Expected Review Behavior

- Classify as ABAC or hybrid.
- Review attribute source, cache TTL, revocation latency, and offboarding invalidation.
- Require a negative test proving an expired contractor is denied immediately or within the documented risk tolerance.

### Failure Mode Caught

Without attribute freshness checks, the skill can accept correct-looking ABAC rules that make stale authorization decisions.
