# PAM Capability Maturity Matrix

> Extracted from `privileged-access/SKILL.md` Step 2. Use for assessing PAM tool effectiveness.

## PAM Capability Assessment Matrix

| Capability | Not Present | Basic | Mature | Advanced |
|---|---|---|---|---|
| **Credential Vaulting** | Credentials in plaintext/spreadsheets | Vault deployed, partial onboarding | All privileged credentials vaulted | Auto-discovered, auto-onboarded, auto-rotated |
| **Session Management** | No privileged session controls | Session proxy for some systems | Session proxy for all critical systems | Session recording + real-time monitoring + termination |
| **JIT Access** | Standing privileges only | Manual request/approval process | Automated JIT with approval workflows | Risk-adaptive JIT with behavioral analytics |
| **Password Rotation** | Manual or no rotation | Scheduled rotation (e.g., 90 days) | Automatic rotation after each use | Dynamic credentials (ephemeral, single-use) |
| **Discovery** | Manual inventory | Periodic scan for privileged accounts | Continuous discovery and alerting | Auto-onboarding of discovered privileged accounts |
| **Analytics** | No privileged activity analytics | Basic usage reports | Anomaly detection on privileged sessions | ML-driven behavioral analytics with automated response |

## Credential Management Hierarchy (prefer top)

| Tier | Method | Risk Level | Example |
|---|---|---|---|
| **Tier 1** | Ephemeral / dynamic credentials | Lowest | HashiCorp Vault dynamic secrets, AWS STS, Azure Managed Identity |
| **Tier 2** | Vaulted with auto-rotation | Low | CyberArk CPM rotation, Vault lease-based secrets |
| **Tier 3** | Vaulted with manual rotation | Medium | Vault with manual rotation schedule, Azure Key Vault |
| **Tier 4** | Managed secrets without vault | High | AWS Secrets Manager without rotation, encrypted config files |
| **Tier 5** | Plaintext / unmanaged | Critical | Environment variables, hardcoded in source, spreadsheets |

## JIT Maturity Levels

| Level | Description | Characteristics |
|---|---|---|
| **Level 0 — None** | Standing privileges | All admins have permanent access, no elevation workflow |
| **Level 1 — Requested** | Manual JIT | Request via ticket, manual provisioning, manual revocation |
| **Level 2 — Managed** | Automated JIT | PAM-managed elevation, approval workflows, automatic expiry |
| **Level 3 — Adaptive** | Risk-based JIT | Context-aware approval, behavioral analytics, ephemeral credentials |

## Session Recording Capability Matrix

| Capability | Not Present | Basic | Mature | Advanced |
|---|---|---|---|---|
| **Protocol coverage** | None | SSH only | SSH + RDP + web | SSH + RDP + web + database + API |
| **Recording type** | None | Metadata only (who, when, where) | Full session replay (video/text) | Full replay + indexed search + command extraction |
| **Storage** | None | Local to PAM | Forwarded to secure storage | Immutable storage with integrity verification |
| **Monitoring** | None | Post-hoc review | Near-real-time alerts on keywords | Real-time behavioral analytics with auto-termination |
| **Retention** | None | < 90 days | 12 months | Policy-driven, aligned with regulatory requirements |
