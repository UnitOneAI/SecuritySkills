# Agent Security — Blast Radius Assessment Framework

## Blast Radius Assessment Matrix

| If Agent Is Compromised | Question | Worst Case If No Control |
|---|---|---|
| Data exfiltration | What data can it access and where can it send it? | All data in the system exfiltrated to attacker |
| Data destruction | What data can it delete or corrupt? | Production data loss |
| Lateral movement | What other systems can it reach? | Pivot to other agents, services, infrastructure |
| Persistent access | Can it create backdoors, new credentials, or modify configs? | Persistent attacker presence survives agent termination |
| External impact | What irreversible external actions can it take? | Emails sent, APIs called, code deployed, money transferred |
| Resource exhaustion | How much compute/cost can it consume? | Unbounded API spend, denial of service |

## Rollback Capability Assessment

| Action Category | Examples | Rollback Approach | Minimum Requirement |
|---|---|---|---|
| Database writes | INSERT, UPDATE, DELETE | Transaction rollback, soft delete | Point-in-time recovery; logged |
| File modifications | Create, overwrite, delete | Version history, backup before modify | Previous version retained |
| Code deployment | Ship code, update config | Blue-green deploy, feature flags, version rollback | One-click rollback to previous version |
| External API calls | Webhook, partner API | Compensating API call (if supported) | Documented manual recovery procedure |
| Communications | Email, Slack, notification | Cannot recall; use draft/review mode | HITL gate before send; draft mode |
| Financial transactions | Payment, transfer | Reversal transaction (if supported) | HITL gate; hold period; reversal procedure |
| Infrastructure changes | Provision, modify, destroy | IaC state rollback, destroy and recreate | IaC-managed with state history |
