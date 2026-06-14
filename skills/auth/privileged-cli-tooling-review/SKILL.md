---
name: privileged-cli-tooling-review
category: auth
severity: high
---

# Privileged CLI Tooling Review

## What It Detects
Privileged command-line tools can bypass web-layer controls and logging if tokens, profiles, and impersonation capabilities are too broad.

## Why This Skill Is Needed
This topic appears in real security reviews, but it is not represented cleanly in the current library. A dedicated skill would make the review repeatable and easier to apply across products.

## Detection Steps
1. **Identify Privileged CLI Tools**: Inventory all CLI tools used by the application or infrastructure that require elevated permissions (e.g., `sudo`, `aws`, `kubectl`, `terraform`).
2. **Review Token & Profile Configuration**:
   - Check if CLI tools use long-lived static credentials instead of short-lived tokens.
   - Verify if profiles allow broad impersonation (e.g., `--assume-role` without MFA).
3. **Audit Logging & Monitoring**:
   - Ensure all CLI actions are logged to a centralized SIEM.
   - Verify that logs include user identity, timestamp, command, and outcome.
4. **Check Access Controls**:
   - Validate that CLI access is restricted to authorized users/groups.
   - Ensure least-privilege principles are applied to CLI permissions.
5. **Test for Bypass**:
   - Attempt to execute commands that would be blocked by web-layer controls via the CLI.
   - Verify if rate limiting or anomaly detection applies to CLI usage.

## Remediation
- Enforce short-lived, scoped tokens for CLI access.
- Require MFA for all privileged CLI operations.
- Implement strict logging and alerting for CLI usage.
- Regularly audit and rotate CLI credentials.
- Restrict CLI access to specific IP ranges or environments where possible.

## References
- [OWASP CLI Security](https://owasp.org/www-project-cheat-sheets/cheatsheets/Command_Line_Interface_Cheat_Sheet.html)
- [NIST SP 800-53: Access Control](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)