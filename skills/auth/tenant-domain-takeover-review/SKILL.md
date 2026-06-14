# tenant-domain-takeover-review

## Overview
This skill identifies risks associated with tenant domain takeover in multi-tenant SaaS applications. It focuses on scenarios where DNS records, email verification flows, or organizational ownership claims are insufficiently validated, allowing attackers to hijack tenant domains or intercept invites.

## Category
auth

## Severity
high

## What It Detects
Tenant domain verification and invite routing can be hijacked when:
- DNS CNAME/NS records point to unclaimed or expired resources.
- Email trust mechanisms rely on unverified domains.
- Organizational ownership semantics allow arbitrary domain claims without strong proof-of-control.
- Invite routing logic does not strictly validate the target tenant's domain ownership before sending sensitive links.

## Why This Skill Is Needed
Real-world security reviews frequently uncover tenant domain takeovers where attackers register expired domains previously used by a SaaS tenant, or exploit weak email verification to redirect invites. This skill standardizes the detection of these patterns, ensuring consistent coverage across products.

## Detection Approach
1. **DNS Record Analysis**: Scan for CNAME or NS records pointing to external services that are not actively claimed by the tenant (e.g., pointing to a generic SaaS endpoint without a unique subdomain claim).
2. **Email Trust Validation**: Review email verification flows to ensure domains are validated via DNS TXT records or similar proof-of-control mechanisms before trust is established.
3. **Org Ownership Semantics**: Audit the logic for claiming or transferring tenant ownership to ensure it requires strong cryptographic or administrative proof, not just email confirmation.
4. **Invite Routing Logic**: Trace the path of tenant invite emails to ensure the destination domain is validated against the current tenant configuration and not derived from user input without verification.

## Indicators of Compromise (IoC)
- CNAME records pointing to `*.example.com` without a corresponding unique tenant claim.
- Email verification emails sent to domains that have not passed DNS TXT validation.
- Invite links generated for domains that are not currently active or verified in the tenant registry.
- Absence of rate limiting or anomaly detection on domain claim requests.

## Remediation
- Implement strict DNS proof-of-control (e.g., requiring a specific TXT record) before allowing domain association.
- Ensure invite routing logic validates the target domain against the current, verified tenant configuration.
- Deprecate email-only verification for critical ownership changes; require MFA or admin approval.
- Monitor for DNS record changes that point to unclaimed resources and alert on potential takeover attempts.

## References
- [OWASP: Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- [SANS: Domain Takeover Prevention](https://www.sans.org/blog/preventing-domain-takeover-attacks/)