# Effective Access Expansion Fixture

Use this fixture to validate that access-review output includes inherited access paths, not only direct grants.

## Review Input

```text
user: finance.contractor@example.com
direct grants: none
idp path: Okta dynamic group "finance-active-contractors" -> Entra group "finance-prod-admins" -> SaaS role "Billing Admin"
dynamic rule: department == "Finance" AND employment_status == "active" AND contractor_end_date > today()
rule owner: finance-it
source attributes: HRIS department, HRIS employment_status, vendor-management contractor_end_date
last evaluated: 2026-06-04T09:15:00Z
scim mapping: Entra group "finance-prod-admins" maps to SaaS role "Billing Admin"
mapping last reconciled: 2026-06-04T09:30:00Z
break-glass group: billing-emergency-admins, owner billing-platform, empty during review
cycle check: group graph traversal rejected finance-prod-admins -> finance-reviewers -> finance-prod-admins
```

## Expected Review Requirements

- Flag missing effective-access expansion when the review packet only lists direct grants.
- Include the nested group path from user to final SaaS role.
- Include dynamic rule owner, source attributes, and last evaluation timestamp.
- Include SCIM or external IdP mapping evidence for the downstream SaaS role.
- Reject circular group nesting as unauditable until the loop is removed or explicitly bounded.
- Preserve break-glass owner and activation evidence even when the group is empty during review.

## Expected Finding Shape

```text
Finding ID: AR-CERT-09
Title: Access review certifies only direct grants and omits inherited admin access
Access Path: Okta dynamic group -> Entra nested group -> SaaS Billing Admin role
Expansion Freshness: dynamic rule evaluated 2026-06-04T09:15:00Z; SCIM mapping reconciled 2026-06-04T09:30:00Z
Evidence: direct grants are empty, but effective-access expansion shows Billing Admin access through nested and dynamic IdP groups
Remediation: expand nested groups, dynamic group rules, and SCIM mappings before presenting certification decisions
```
