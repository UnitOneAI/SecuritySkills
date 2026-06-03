# Vulnerable: Current SBOM Format Downgraded by Stale Parser

## Scenario

A review tool only recognizes CycloneDX 1.5 and SPDX 2.3, then marks newer SBOMs
as unknown instead of recording a parser limitation.

## Sample Evidence

```text
document_a=bomFormat CycloneDX specVersion 1.6
document_b=SPDX Specification 3.0.1 model/profile structure
parser_baseline=legacy tool with CycloneDX 1.5 and SPDX 2.3 assumptions
review_result=Unknown format, not analyzed
minimum_elements_baseline=not recorded
artifact_digest=missing
```

## Expected Handling

- Do not downgrade current SBOM formats to unknown solely because tooling is
  stale.
- Record parser baseline and version-handling status.
- Mark artifact binding and minimum-elements baseline as Not Evaluable until
  reviewed with compatible parsing or explicit field mapping.

