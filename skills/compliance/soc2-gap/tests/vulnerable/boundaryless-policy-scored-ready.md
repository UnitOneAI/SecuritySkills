# Vulnerable: boundaryless policy scored ready

## Scenario

The assessor is reviewing CC6.1 and CC6.2 for a SaaS platform with a production app, an admin console, a managed database provider, and customer-managed tenant identity providers.

## Input Evidence

- Access control policy says MFA is required for administrative access.
- The policy does not list covered systems, owner, data class, production cloud account, admin console, or managed database access path.
- Customer tenant SSO is mentioned in the onboarding guide, but the guide does not identify whether it is a service-organization control or a CUEC.
- Vendor database access is covered by a vendor SOC 2 report, but no carve-out/inclusive decision or CUEC/CSOC mapping is documented.

## Incorrect Result The Skill Should Prevent

```text
CC6.1 score: 4
CC6.2 score: 4
Reason: MFA policy exists and vendor SOC 2 report is available.
```

## Expected Handling

The skill should mark the affected criteria as `Not evaluable - boundary unresolved` or partial until the evidence maps to stable boundary IDs, component owners, data classes, and subservice/CUEC treatment. A generic policy alone should not prove coverage for every in-scope system component.
