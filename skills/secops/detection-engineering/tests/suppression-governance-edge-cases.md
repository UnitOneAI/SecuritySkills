# Detection Suppression Governance Edge Cases

Use these cases to calibrate whether a detection tuning change preserves ATT&CK coverage.

## Vulnerable: overbroad encoded PowerShell suppression

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: b5c2a0a0-7d5a-4b8c-9c3f-1a2b3c4d5e6f
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  filter_admin_hosts:
    Computer|contains: 'ADMIN'
  condition: selection_process and selection_encoded and not filter_admin_hosts
falsepositives:
  - Admin maintenance scripts
level: medium
```

Expected review outcome:

- Fail: the suppression scope is broad and can hide encoded PowerShell on any host containing `ADMIN`.
- Fail: no owner, approval, expiry, benign sample, or ticket is recorded.
- Fail: no regression evidence proves a malicious encoded command on admin infrastructure still fires.
- Fail: no coverage impact is recorded for ATT&CK T1059.001 or T1027.

## Benign: narrow suppression with regression evidence

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: b5c2a0a0-7d5a-4b8c-9c3f-1a2b3c4d5e6f
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  filter_sccm_signed_client:
    ParentImage|endswith: '\ccmexec.exe'
    ParentCommandLine|contains: 'ConfigurationManager'
    ParentSignatureStatus: 'Valid'
    ParentSignatureSubject|contains: 'Microsoft Corporation'
  condition: selection_process and selection_encoded and not filter_sccm_signed_client
falsepositives:
  - SCCM client operations approved in SEC-123, owner Endpoint Engineering, review 2026-09-30
level: medium
```

Expected review outcome:

- Pass: the suppression is tied to a specific parent process, command pattern, and signer evidence.
- Pass: owner, ticket, business reason, and review date are recorded.
- Needs evidence: the PR or ADS should attach sample benign events and a true-positive regression event proving unrelated encoded PowerShell still alerts.
- Needs evidence: coverage impact should be recorded as unchanged or reduced with compensating detection.
