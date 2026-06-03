# API Security Assessment

API:
Environment:
Assessed by:
Date:
Framework sources:

## Inventory

| Route | Method | AuthN | Caller type | Object scope | Notes |
| --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |

## Authorization Tests

| Test | Expected behavior | Observed behavior | Evidence confidence | Result |
| --- | --- | --- | --- | --- |
| Object-level authorization |  |  | High / Medium / Low | Pass / Fail / Not Evaluable |
| Function-level authorization |  |  | High / Medium / Low | Pass / Fail / Not Evaluable |
| Property-level authorization |  |  | High / Medium / Low | Pass / Fail / Not Evaluable |

## OWASP API Security Top 10 2023 Mapping

| Category | Result | Evidence |
| --- | --- | --- |
| API1 Broken Object Level Authorization |  |  |
| API2 Broken Authentication |  |  |
| API3 Broken Object Property Level Authorization |  |  |
| API4 Unrestricted Resource Consumption |  |  |
| API5 Broken Function Level Authorization |  |  |
| API6 Unrestricted Access to Sensitive Business Flows |  |  |
| API7 Server Side Request Forgery |  |  |
| API8 Security Misconfiguration |  |  |
| API9 Improper Inventory Management |  |  |
| API10 Unsafe Consumption of APIs |  |  |

## Verification Gate

- Route inventory covers unauthenticated, user, partner, admin, and service calls.
- Tests include expected behavior, observed behavior, and evidence confidence.
- SAST rules or suppressions include owner, reason, expiry, and revalidation.
