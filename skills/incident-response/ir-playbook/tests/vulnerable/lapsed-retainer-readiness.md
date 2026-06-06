# Vulnerable: lapsed IR retainer treated as escalation-ready

## Scenario

- Incident: SEV-1 ransomware with suspected data exfiltration
- External support field: "MSSP on retainer"
- Cyber insurance policy effective date: 2026-01-01 through 2026-12-31
- IR retainer SOW end date: 2025-12-31
- Hotline test: never performed
- Remaining retainer hours: unknown
- Overage approval: not documented

## Expected Findings

- `IR-RET-01` because the referenced IR retainer is expired.
- `IR-RET-02` because the 24x7 activation channel has not been tested.
- `IR-RET-05` because remaining hours and spend authority are unknown.

## Why This Matters

The playbook cannot treat external IR engagement as ready when the only current document is an insurance policy and the actual IR SOW has lapsed.
