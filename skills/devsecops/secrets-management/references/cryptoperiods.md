# NIST SP 800-57 Cryptoperiods

Reference: NIST SP 800-57 Part 1 Rev 5, Section 5.3

| Secret Type | Recommended Max Cryptoperiod | Rotation Method |
|-------------|------------------------------|-----------------|
| Database credentials | 90 days | Vault dynamic secrets, Secrets Manager rotation Lambda |
| API keys | 90 days | Provider API key rotation, dual-key rollover |
| TLS certificates | 398 days (CA/B Forum max), 90 days preferred | ACME (Let's Encrypt), cert-manager |
| SSH keys | 1 year | SSH CA with short-lived certificates preferred |
| Service account keys | 90 days | Workload identity federation preferred (no keys) |

## Key States (NIST SP 800-57 Section 5.2)

| State | Description |
|-------|-------------|
| Pre-activation | Key generated but not yet authorized for use |
| Active | Key authorized for cryptographic operations |
| Deactivated | Key no longer used for new operations; may still decrypt existing data |
| Compromised | Key integrity or confidentiality breached; must be revoked immediately |
| Destroyed | Key material permanently erased |

Source: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
