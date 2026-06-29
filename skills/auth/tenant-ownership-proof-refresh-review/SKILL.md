---
name: tenant-ownership-proof-refresh-review
category: auth
severity: high
---

# Tenant Ownership Proof Refresh Review

## What It Detects
Long-lived tenant ownership assertions can become unsafe when proof is not refreshed after meaningful changes in domain control, leadership, or trust relationships.

## Why This Skill Is Needed
Ownership proof is often treated as a one-time setup event, but real organizations change. A dedicated skill would help reviewers inspect whether sensitive actions depend on stale ownership claims that haven't been re-verified against current domain records, admin lists, or trust anchors.

## Detection Criteria
1. **Stale Proof Tokens**: Identify tokens or signatures used for tenant ownership that were generated >90 days ago (or per policy) without a refresh mechanism.
2. **Missing Re-verification**: Check for critical actions (e.g., data export, admin role assignment, domain transfer) that do not trigger a re-verification of the ownership proof.
3. **Domain Control Drift**: Detect scenarios where the domain's DNS records or WHOIS data have changed since the initial ownership proof was established, but the system still trusts the old proof.
4. **Leadership/Trust Anchor Changes**: Flag cases where the list of authorized signers or trust anchors has been updated, but the tenant's ownership proof hasn't been re-signed by the new set.

## Remediation Steps
- Implement a time-based expiration for ownership proof tokens (e.g., 30-90 days).
- Require re-verification of ownership proof before executing high-risk actions.
- Integrate with domain monitoring services to detect changes in DNS/WHOIS and invalidate stale proofs automatically.
- Enforce multi-party re-signing of ownership proofs when the list of authorized admins changes.

## Example Code Snippet (Vulnerable)