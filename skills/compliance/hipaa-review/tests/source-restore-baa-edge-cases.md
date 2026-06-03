# HIPAA Source, Restore, and BAA Evidence Edge Cases

These cases calibrate the `hipaa-review` skill against source freshness,
recoverability evidence, and Business Associate Agreement clause review. They
are not legal advice and should be used only as review fixtures.

## Case 1: Benign Source-Dated Penalty Reference

```text
Finding draft:
  Civil monetary penalty reference is based on an HHS/OCR source.
Source register:
  Source: HHS/OCR penalty notice
  Publication/effective date: 2025-10-06
  Reviewed date: 2026-06-03
  Claim supported: inflation-adjusted penalty tier range used in appendix
  Confidence: High
  Report use: finding appendix
```

Expected handling:
- Allow the penalty reference only with the registered source, date, and claim.
- Keep the finding focused on the HIPAA control gap, not the dollar amount.

## Case 2: Vulnerable Stale Penalty Claim

```text
Finding draft:
  "Annual maximum is $2,067,813 as of 2024."
Evidence:
  Source URL: missing
  Effective year: missing
  Reviewed date: missing
```

Expected handling:
- Mark as `Not Evaluable from Stale Source`.
- Remove the dollar amount from client-facing findings until an official current
  source is recorded.

## Case 3: Threat Intel Without Provenance

```text
Risk analysis:
  Named healthcare wiper incident cited.
Missing:
  Publication date
  Source authority
  Attribution confidence
  Affected sector
  HIPAA safeguard mapping
```

Expected handling:
- Do not turn the named incident into a compliance finding.
- Reframe as a generic destructive-malware scenario unless a source-register row
  supports the claim.

## Case 4: Backup Policy Without Restore Evidence

```text
Evidence:
  Backup policy exists
  Console screenshot shows immutable backups enabled
Missing:
  Restore test date
  Restored system or ePHI data class
  RPO/RTO result
  Integrity verification
  Deletion-protection or administrator-compromise test
```

Expected handling:
- Do not mark 164.308(a)(7)(ii)(A)-(E) fully supported.
- Require `Contingency and Restore Evidence` before concluding recoverability.

## Case 5: BAA Exists But Clause Evidence Is Missing

```text
Vendor:
  transcription-saas.example
BAA:
  present
Missing:
  Subcontractor flow-down terms
  Security incident notice trigger and timing
  Termination and return/destruction clause
  Last review date
```

Expected handling:
- Mark as `Not Evaluable from Missing Clause Evidence`.
- Do not treat BAA existence alone as enough for 164.308(b)(1) or 164.314(a).
