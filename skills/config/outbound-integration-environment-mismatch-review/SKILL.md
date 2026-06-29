# Outbound Integration Environment Mismatch Review

## Category
Config

## Severity
Medium

## What It Detects
Outbound integrations can leak production data into lower-trust systems when environment labeling, credential routing, and delivery configuration are not bound consistently. This skill detects such environment mismatches.

## Why This Skill Is Needed
Environment mismatch is a recurring cause of accidental data exposure, especially in webhook and API integrations. A dedicated skill helps identify and mitigate these risks.

## How to Use
1. Review outbound integration configurations.
2. Ensure consistent environment labeling.
3. Verify credential routing matches the environment.
4. Check delivery configurations for environment-specific settings.

## Best Practices
- Use environment-specific credentials for integrations.
- Label environments clearly in integration configurations.
- Regularly audit integration configurations for environment mismatches.