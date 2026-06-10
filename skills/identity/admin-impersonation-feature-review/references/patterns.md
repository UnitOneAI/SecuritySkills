# Admin Impersonation Review Patterns

## Vulnerable Patterns

| Pattern | Why it matters | Review signal |
|---|---|---|
| Target-only session minting | Staff identity is lost | `session.userId = targetUserId` with no actor claim |
| No reason or ticket requirement | Abuse cannot be justified or investigated | empty `reason`, optional `ticketId` |
| Tenantless target lookup | Staff can cross customer boundaries | `findUser(targetUserId)` without tenant condition |
| Full customer permissions during impersonation | Staff can perform sensitive actions as the customer | no deny list or scope check for writes |
| Normal refresh token reuse | Impersonation persists like a customer login | refresh token minted for target user |
| Target-only audit events | Staff activity looks like customer activity | `actor=userId` where userId is the target |
| No UI or API marker | Users and reviewers cannot detect impersonation | missing `isImpersonating` session flag |
| Timeout not enforced | Temporary access becomes standing access | no expiry or revocation listener |

## Safe Patterns

| Control | Expected evidence |
|---|---|
| Server-side approval gate | ticket, reason, approver, scope, expiry before session creation |
| Dual identity claims | `actor_id`, `target_user_id`, `tenant_id`, `scope`, `expires_at` |
| Read-only default scope | high-risk writes denied unless explicitly approved |
| Tenant assignment check | actor support assignment matches target tenant |
| Immutable audit trail | session start, action, scope change, and end events include actor and target |
| Visible session marker | UI banner and API context expose impersonation state |
| Short lifetime | absolute timeout and revocation on approval or assignment change |

## Suggested Search Terms

- `impersonate`, `loginAs`, `actAs`, `viewAs`, `supportSession`
- `targetUserId`, `actorId`, `adminId`, `staffId`, `reason`, `ticket`
- `isImpersonating`, `impersonationSession`, `originalUser`
- `audit`, `session.start`, `session.end`, `readOnly`
- `tenantId`, `workspaceId`, `assignment`, `approval`

## Review Questions

1. Can staff create a session with only a target user ID?
2. Does every impersonated request carry both actor and target identity?
3. Are billing, security, export, destructive, and consent-like actions blocked?
4. Is cross-tenant target selection impossible server-side?
5. Are session start, every action, and session end audited immutably?
6. Can approval or assignment revocation terminate the active session?
