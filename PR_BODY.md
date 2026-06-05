Fixes #1187.

## Summary
- Adds a SignalR hub security section to the .NET API security supplement.
- Covers hub inventory, browser credential/origin evidence, method/group authorization, query-string access-token handling, and buffer/detailed-error controls.
- Adds grep patterns and Microsoft SignalR security/auth references.

## Verification
- `git diff --check`
- Markdown code fence balance check
- Required marker checks for `MapHub`, hub authorization, `Groups.AddToGroupAsync`, `access_token`, buffer limits, and SignalR references.

## Bounty
Requesting consideration under the SecuritySkills bounty program as an Improver contribution. Preferred payment method can be provided privately after acceptance.
