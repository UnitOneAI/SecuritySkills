# NIST RBAC Model and SP 800-162 Reference

> Extracted from `rbac-design/SKILL.md` for reuse across identity skills.

## NIST RBAC Model (ANSI INCITS 359-2012) — Key Definitions

| Term | Definition (per ANSI INCITS 359-2012) |
|---|---|
| **User** | A human being or autonomous agent |
| **Role** | A job function within the context of an organization with associated semantics regarding authority and responsibility |
| **Permission** | An approval to perform an operation on one or more protected objects |
| **Session** | A mapping of one user to potentially many roles |
| **User Assignment (UA)** | Many-to-many mapping of users to roles |
| **Permission Assignment (PA)** | Many-to-many mapping of permissions to roles |

## NIST RBAC Model Levels

| Model Level | Name | Components | Use Case |
|---|---|---|---|
| **RBAC0** | Core RBAC | Users, Roles, Permissions, Sessions, User-Role Assignment, Permission-Role Assignment | Basic role assignment — minimum viable RBAC |
| **RBAC1** | Hierarchical RBAC | Core + Role Hierarchies (general and limited) | Organizational structures where senior roles inherit junior permissions |
| **RBAC2** | Constrained RBAC | Core + Constraints (SoD, cardinality, prerequisite roles) | Environments requiring segregation of duties enforcement |
| **RBAC3** | Symmetric RBAC | Hierarchical + Constrained (RBAC1 + RBAC2) | Full enterprise RBAC with hierarchies and policy constraints |

## NIST SP 800-162 — ABAC Planning Considerations (Section 5)

| Consideration | Description |
|---|---|
| **Attribute Assurance** | Attributes must come from authoritative, trusted sources with integrity protections |
| **Policy Completeness** | Policies must cover all access scenarios; implicit deny for unmatched requests |
| **Attribute Granularity** | Attributes must be granular enough to express required policies without over-engineering |
| **Performance** | PDP evaluation latency must meet application SLA requirements |
| **Interoperability** | Standards-based attribute formats (XACML, ALFA, OPA/Rego, Cedar) for portability |
| **Auditability** | All policy evaluations logged with input attributes and decision rationale |

## Sources

- Sandhu, R., Ferraiolo, D., Kuhn, R. — "The NIST Model for Role-Based Access Control" (ACM RBAC 2000): https://csrc.nist.gov/projects/role-based-access-control
- ANSI INCITS 359-2012 — Role Based Access Control (RBAC) standard
- NIST SP 800-162, Guide to Attribute Based Access Control (ABAC) Definition and Considerations: https://csrc.nist.gov/publications/detail/sp/800-162/final
