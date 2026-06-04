# Benign: boundary-traced access control evidence

## Scenario

The assessor is reviewing CC6.1 and CC6.2 for a SaaS platform whose SOC 2 boundary is already documented.

## Boundary Register

| Boundary ID | Component | Type | Scope Status | Owner | Evidence Source | Category Link |
|-------------|-----------|------|--------------|-------|-----------------|---------------|
| INF-01 | Production AWS account | Infrastructure | In scope | Platform | Cloud inventory, architecture diagram | Security |
| APP-01 | Admin console | Software | In scope | Engineering | Deployment records, access review export | Security |
| VEN-01 | Managed database provider | Subservice organization | Carve-out | Vendor owner | Vendor SOC 2, CUEC/CSOC matrix | Security |
| CUST-01 | Customer tenant IdP | User entity control | CUEC | Customer | Contract, onboarding guide | Security |

## Evidence

- MFA policy maps administrative access to INF-01 and APP-01.
- Quarterly access review export lists privileged users for INF-01 and APP-01.
- VEN-01 is documented as carve-out with CUECs assigned to the service organization and customer where applicable.
- CUST-01 tenant MFA is documented as a customer responsibility in the contract and onboarding guide.

## Expected Handling

The skill may score CC6.1 and CC6.2 as ready or partially ready based on operating-effectiveness evidence because each claim traces to boundary IDs and the customer-owned control is handled as a CUEC instead of a missing service-organization control.
