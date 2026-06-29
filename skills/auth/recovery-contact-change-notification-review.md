# Recovery Contact Change Notification Review

## Category
auth

## Severity
medium

## Description
This skill reviews the process of changing recovery contacts to ensure it is secure and properly notified.

## What It Detects
Recovery contact changes can silently weaken account safety if not handled properly. This skill detects whether the system has adequate measures such as notifications, cooldowns, and actor binding when changing recovery contacts.

## Why This Skill Is Needed
Changing recovery channels is a common precursor to account takeover. A dedicated skill helps reviewers inspect whether these changes are treated with the necessary security measures.

## How to Review
1. Check if the system sends notifications upon recovery contact changes.
2. Verify if there are cooldowns or delays before the change takes effect.
3. Ensure that the actor making the change is properly authenticated and authorized.

## Best Practices
- Implement immediate notification upon recovery contact change.
- Introduce a cooldown period before the recovery contact change is effective.
- Ensure strong actor binding to prevent unauthorized changes.