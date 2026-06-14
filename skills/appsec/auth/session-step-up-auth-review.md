# Session Step-up Authentication Review
## Category: auth
## Severity: high

### Description
Sensitive actions often rely on stale sessions instead of fresh step-up authentication, especially after role changes or long-lived background presence.

### What It Detects
This skill detects when an application or system fails to enforce step-up authentication for sensitive actions, potentially allowing unauthorized access due to stale sessions.

### Why This Skill Is Needed
This topic is crucial in real security reviews but is not cleanly represented in the current library. A dedicated skill makes the review process repeatable and easier to apply across different products.

### Audit Steps
1. Identify sensitive actions within the application or system.
2. Review authentication mechanisms for these actions.
3. Check if step-up authentication is enforced after role changes or prolonged inactivity.
4. Verify that session management practices prevent stale sessions from being used for sensitive actions.

### Remediation Steps
1. Implement step-up authentication for sensitive actions.
2. Ensure that role changes trigger re-authentication or step-up authentication.
3. Configure session management to timeout or require re-authentication after a reasonable period of inactivity.

### References
- [Insert relevant references or guidelines on step-up authentication and session management]