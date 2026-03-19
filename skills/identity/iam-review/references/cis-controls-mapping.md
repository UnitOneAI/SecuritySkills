# CIS Controls v8 Mapping — IAM Review

> Extracted from `iam-review/SKILL.md` for reuse across identity skills.

## Control 5 — Account Management

| Sub-Control | Title | Assessed In |
|---|---|---|
| **5.1** | Establish and Maintain an Inventory of Accounts | Step 1 |
| **5.2** | Use Unique Passwords | Step 2 |
| **5.3** | Disable Dormant Accounts | Step 5 (delegated to access-review skill) |
| **5.4** | Restrict Administrator Privileges to Dedicated Administrator Accounts | Steps 3, 6 (JIT delegated to privileged-access skill) |
| **5.5** | Establish and Maintain an Inventory of Service Accounts | Steps 1, 4 |
| **5.6** | Centralize Account Management | Steps 1, 7 (zero trust delegated to zero-trust-assessment skill) |

## Control 6 — Access Control Management

| Sub-Control | Title | Assessed In |
|---|---|---|
| **6.1** | Establish an Access Granting Process | Step 3 |
| **6.2** | Establish an Access Revoking Process | Step 5 (delegated to access-review skill) |
| **6.3** | Require MFA for Externally-Exposed Applications | Step 2 |
| **6.4** | Require MFA for Remote Network Access | Step 2 |
| **6.5** | Require MFA for Administrative Access | Step 2 |
| **6.6** | Establish and Maintain an Inventory of Authentication and Authorization Systems | Step 1 |
| **6.7** | Centralize Access Control | Step 7 (delegated to zero-trust-assessment skill) |
| **6.8** | Define and Maintain Role-Based Access Control | Step 3 |

## Source

- CIS Controls v8: https://www.cisecurity.org/controls/v8
