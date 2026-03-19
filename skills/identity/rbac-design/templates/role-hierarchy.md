# Role Hierarchy Template

> Extracted from `rbac-design/SKILL.md` Step 2. Use this as a starting pattern for RBAC1 (Hierarchical RBAC) design.

## Recommended Hierarchy Pattern (Max 3 Levels)

```
Level 0 (Base):       employee-base
                      ├── read-only-global
                      └── self-service-portal

Level 1 (Functional): developer          finance-analyst       hr-specialist
                      ├── code-repos      ├── financial-reports  ├── hris-read
                      ├── ci-cd-pipeline  ├── expense-approve    ├── personnel-records
                      └── dev-infra       └── budget-view        └── benefits-admin

Level 2 (Elevated):   senior-developer   finance-manager       hr-manager
                      ├── prod-deploy     ├── journal-entries    ├── personnel-write
                      └── secrets-read    └── audit-reports      └── compensation-view

Level 3 (Admin):      platform-admin     finance-admin         hr-admin
                      (JIT activation)   (JIT activation)      (JIT activation)
```

## Hierarchy Design Principles

1. **Inheritance flows upward** — senior roles inherit all permissions of junior roles
2. **Maximum depth of 3 levels** — deeper hierarchies become unauditable
3. **Separation by function, not by person** — roles reflect job functions, not individuals
4. **Base roles for common access** — everyone gets a base role (e.g., `employee-base`)
5. **Functional roles for job-specific access** — layer on top of base (e.g., `developer`, `finance-analyst`)
6. **Privileged roles for elevated access** — separate from functional roles, require activation
