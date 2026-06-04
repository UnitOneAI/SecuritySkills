# Device Posture Freshness and CAE Fixture

Use this fixture to validate that zero-trust assessments distinguish static compliance checks from current posture evidence that drives access decisions.

## Strong Evidence

```text
device_id: aad-device-123
user: analyst@example.com
posture_sources: Intune MDM, EDR, Entra conditional access, ZTNA gateway
last_mdm_signal: 2026-06-04T10:04:00Z
last_edr_signal: 2026-06-04T10:05:00Z
max_allowed_age: 5 minutes
policy: block if EDR disabled, disk encryption absent, jailbreak detected, or signal stale
failure_mode: fail closed to high-risk SaaS apps; limited access to self-remediation portal
cae_trigger: EDR disabled event revokes active SaaS session within 60 seconds
correlation: same device_id appears in MDM compliance log, EDR health event, IdP policy decision, and ZTNA access log
```

Expected assessment: Optimal candidate for device posture enforcement because posture is fresh, correlated, fail-closed, and tied to session revocation on drift.

## Weak Evidence

```text
device_id: laptop-456
posture_sources: daily CSV export from MDM
last_mdm_signal: 2026-06-03T00:00:00Z
max_allowed_age: undocumented
policy: allow if compliant flag is true
failure_mode: allow until next daily sync
cae_trigger: none
correlation: IdP log records login success but no device posture timestamp
```

Expected finding: ZT-DEV-11 and ZT-DEV-12. The assessment should cap maturity because the compliance signal is stale and active sessions are not revoked or re-evaluated when device posture changes.

## Conflicting Signals

```text
device_id: byod-789
mdm_status: compliant at 2026-06-04T10:00:00Z
edr_status: missing at 2026-06-04T10:01:00Z
ztna_policy: allow
precedence_rule: not documented
failure_mode: not documented
```

Expected finding: ZT-DEV-13. The assessment should require a documented precedence rule and fail-closed handling for conflicting MDM, EDR, IdP, and ZTNA posture signals.
