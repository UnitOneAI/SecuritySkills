# Vulnerable: Critical Regulatory Claim Uses Secondary Sources Only

This fixture should fail because a critical finding cites summaries instead of an official regulator, standards body, contract, or DPA source.

```text
finding: Critical - high-risk AI system lacks privacy controls
regulatory_reference: EU AI Act Article 10 and GDPR Article 35
authoritative_sources:
  - vendor blog summary of EU AI Act obligations
  - consultant checklist copied into the assessment notes
official_source: missing
contract_or_dpa_source: missing
reviewed_date: 2026-06-05
source_status: Secondary
source_confidence: Low
supported_claim: high-risk AI data governance and DPIA obligation
```

Expected result: fail. Critical and High regulatory claims should be Not Evaluable until at least one official or contractual source is recorded with owner, URL or document ID, reviewed date, status, supported claim, and High confidence.
