---
title: api-client-ownership-transfer-review
category: auth
severity: medium
tags: [api, integration, ownership, credentials, rbac]
---

# API Client Ownership Transfer Review

## What It Detects

This skill detects scenarios where API client or integration ownership transfer preserves old operator control because credentials, scopes, and administrative rights are not rotated and rebound atomically.

## Why This Skill Is Needed

Integrations often outlive the person who created them, making ownership transfer a real security event. Without a dedicated review process, a departing employee or contractor might leave their API keys, OAuth tokens, or service account permissions active under a new owner's name, creating a persistent backdoor.

## Detection Criteria

Reviewers should inspect the following during an ownership transfer event:

1. **Credential Rotation**: Verify that all API keys, secrets, and OAuth tokens associated with the client are revoked and regenerated.
2. **Scope Re-evaluation**: Ensure that the new owner's permissions are explicitly defined and do not inherit excessive privileges from the previous owner.
3. **Audit Trail**: Confirm that the transfer event is logged with a clear record of credential revocation and re-issuance.
4. **Service Account Binding**: Check if service accounts are re-bound to the new owner's identity or if they remain loosely attached to the old identity.

## Remediation Steps

- **Immediate Rotation**: Revoke all existing credentials immediately upon transfer initiation.
- **Least Privilege**: Assign the minimum necessary scopes to the new owner.
- **Automated Enforcement**: Implement CI/CD checks or policy-as-code (e.g., OPA, Sentinel) to block transfers without credential rotation.
- **Documentation**: Update integration documentation to reflect the new owner and credential status.

## Example False Positive

A transfer where the API client is purely read-only and the new owner has no administrative rights, and the credentials are automatically rotated by the platform's native transfer mechanism.

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)