---
id: recovery-contact-change-notification-review
name: Recovery Contact Change Notification Review
category: auth
severity: medium
---

# Recovery Contact Change Notification Review

## What It Detects
Recovery contact changes can silently weaken account safety when notifications, cooldowns, and actor binding are not strong enough for the privilege of redirecting future recovery.

## Why This Skill Is Needed
Changing recovery channels is a classic precursor to takeover. A dedicated skill would help reviewers inspect whether these changes are treated with the same rigor as password resets or 2FA changes.

## Detection Criteria
Review the implementation of recovery contact updates for the following:

1. **Notification Requirements**:
   - Is a notification sent to the *old* contact method immediately upon change request?
   - Is a notification sent to the *new* contact method for confirmation?
   - Are notifications sent via a separate, trusted channel (e.g., email + SMS) if the contact is being changed?

2. **Cooldown Periods**:
   - Is there a mandatory waiting period (e.g., 24-72 hours) before the new contact becomes active?
   - Can the user cancel the change during this cooldown period?

3. **Actor Binding**:
   - Is the change request strictly bound to the current session's authentication context (e.g., MFA verified)?
   - Is there rate limiting on recovery contact changes to prevent brute-force attempts?

4. **Audit Logging**:
   - Are all change attempts (success and failure) logged with IP, user agent, and timestamp?
   - Is the log entry visible to the user in their security activity history?

## Remediation
- Implement a dual-notification system (old + new contact).
- Enforce a time-based lockout (cooldown) for new recovery contacts.
- Require re-authentication (MFA) specifically for this action.
- Ensure audit logs are immutable and user-visible.

## References
- OWASP Authentication Cheat Sheet
- NIST SP 800-63B (Digital Identity Guidelines)