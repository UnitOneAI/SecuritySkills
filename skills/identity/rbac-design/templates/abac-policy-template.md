# ABAC Policy Template

> Extracted from `rbac-design/SKILL.md` Step 5. Use this structure when designing ABAC policies per NIST SP 800-162 Section 3.2.

## Policy Structure

```
Policy := {
  PolicyID:    unique identifier,
  Description: human-readable purpose,
  Target:      {resource_type, action_type},
  Condition:   boolean expression over attributes,
  Effect:      Permit | Deny,
  Obligations: actions PEP must perform (logging, notification)
}
```

## Example Policy

```
PolicyID:    "finance-reports-department-match"
Description: "Finance reports accessible only by members of the owning department"
Target:      {resource_type: "financial-report", action: "read"}
Condition:   subject.department == resource.owning_department
             AND subject.clearance >= resource.sensitivity_level
             AND environment.device_compliance == true
Effect:      Permit
Obligations: log_access(subject.id, resource.id, timestamp)
```

## Attribute Categories

| Category | Examples |
|---|---|
| **Subject Attributes** | Role, department, clearance level, location, device posture |
| **Resource Attributes** | Classification, owner, sensitivity label, data type |
| **Action Attributes** | Read, write, delete, approve, execute |
| **Environment Attributes** | Time of day, IP range, threat level, network zone |

## ABAC Functional Architecture (NIST SP 800-162 Section 4)

| Component | Abbreviation | Function |
|---|---|---|
| **Policy Decision Point** | PDP | Evaluates access requests against policies, returns permit/deny |
| **Policy Enforcement Point** | PEP | Intercepts access requests, enforces PDP decisions |
| **Policy Information Point** | PIP | Provides attribute values to PDP from external sources |
| **Policy Administration Point** | PAP | Interface for policy creation, management, and lifecycle |
| **Policy Retrieval Point** | PRP | Stores and retrieves policies for PDP consumption |

## When ABAC Adds Value Over Pure RBAC

| Scenario | Why RBAC Falls Short | ABAC Policy Pattern |
|---|---|---|
| Multi-tenant data isolation | Roles per tenant cause explosion | `subject.tenant_id == resource.tenant_id` |
| Data classification enforcement | Roles per classification level are rigid | `subject.clearance >= resource.classification` |
| Time-based access windows | Temporal roles are operationally complex | `environment.time within resource.access_window` |
| Geographic restrictions | Per-region roles do not scale | `subject.location in resource.allowed_regions` |
| Owner-based access | Separate role per owner is impractical | `subject.id == resource.owner_id OR subject.role == 'admin'` |
| Risk-adaptive access | Static roles cannot respond to risk signals | `environment.risk_score < resource.max_risk_threshold` |
