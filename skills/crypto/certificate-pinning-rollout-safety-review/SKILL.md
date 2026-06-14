---
title: Certificate Pinning Rollout Safety Review
category: crypto
severity: medium
tags:
  - certificate-pinning
  - rollout
  - rotation
  - client-security
---

# Certificate Pinning Rollout Safety Review

## What It Detects
This skill identifies risks associated with certificate pinning changes where rotation, fallback, and emergency-recovery paths are not designed together. It specifically looks for:
- Hardcoded pins without a secondary backup pin.
- Immediate cutover strategies without a gradual rollout or canary phase.
- Lack of a "panic button" or emergency disable mechanism in the client logic.
- Missing validation for pin expiration dates relative to the rollout schedule.

## Why This Skill Is Needed
Certificate pinning is a powerful defense against MITM attacks, but it introduces significant operational risk. A mismanaged rollout can:
1. **Break Client Connectivity:** If the new certificate is not pinned correctly or the old one expires before the update reaches all users, legitimate traffic is blocked.
2. **Force Unsafe Bypasses:** Developers or users, facing widespread outages, may disable pinning entirely in production to restore service, leaving the application vulnerable.
3. **Hinder Incident Response:** Without a clear fallback path, recovering from a compromised pin or a failed rotation becomes a manual, time-consuming process.

## Review Checklist

### 1. Rotation Strategy
- [ ] **Dual Pinning:** Is there at least one backup pin (e.g., a future certificate or a different CA) active before the primary pin is rotated?
- [ ] **Overlap Period:** Is there a defined overlap period where both the old and new pins are valid?
- [ ] **Update Mechanism:** How are new pins distributed to clients? Is it via a secure, versioned configuration endpoint rather than hardcoded in the binary?

### 2. Fallback & Recovery
- [ ] **Emergency Disable:** Is there a remote configuration flag or "kill switch" to disable pinning in case of a critical rollout failure?
- [ ] **Graceful Degradation:** If pinning fails, does the client fail closed (block) or fail open (log and warn)? *Note: Failing open is generally unsafe, but a controlled fallback to a known-good state is preferred over a hard crash.*
- [ ] **Versioning:** Are pin configurations versioned to allow clients to roll back to a previous valid state if the new one is rejected?

### 3. Client Implementation
- [ ] **Expiration Checks:** Does the client logic check the certificate's `NotAfter` date against the pin's validity window?
- [ ] **Error Handling:** Are pinning failures logged with sufficient detail (e.g., expected vs. received hash) to aid in debugging without leaking sensitive info?
- [ ] **Testing:** Are there automated tests simulating pin rotation and expiration in a staging environment?

## Remediation Steps
1. **Implement Dual Pinning:** Always maintain at least two valid pins. Rotate one while the other remains active.
2. **Adopt Remote Configuration:** Move pin data out of the binary. Use a secure, signed configuration file that can be updated without an app store release.
3. **Define a Rollback Plan:** Ensure the client can revert to a previous configuration version if the new one causes issues.
4. **Staged Rollout:** Deploy pinning changes to a small percentage of users first (canary) before a full rollout.
5. **Monitor and Alert:** Set up alerts for pinning validation failures to detect issues before they impact a large user base.

## References
- [OWASP Certificate Pinning](https://cheatsheetseries.owasp.org/cheatsheets/Certificate_Pinning_Cheat_Sheet.html)
- [Google's Transport Security](https://developers.google.com/android/reference/com/google/android/gms/nearby/connection/TransportSecurity)
- [Mozilla's Pinning Best Practices](https://wiki.mozilla.org/Security/Certificate_Pinning)