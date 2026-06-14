# Support Bot Action Approval Review

## Description
This skill detects support bots capable of triggering account or billing actions, ensuring they have appropriate approval and actor separation mechanisms in place.

## Severity
Medium

## Category
Auth

## Detect
To detect support bots that require stronger approval:
1. Review the configuration and permissions of support bots.
2. Check for separation of duties between the bot's actions and approval processes.
3. Ensure logging and monitoring are in place for bot actions.

## Why This Skill Is Needed
Support bots with the ability to perform significant actions pose a risk if not properly controlled. This skill helps in identifying and mitigating such risks.

## Related Skills
- Other auth related skills

## References
- Relevant documentation or guidelines on support bot security