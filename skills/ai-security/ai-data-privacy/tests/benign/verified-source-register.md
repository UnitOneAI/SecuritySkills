# Benign: Verified Source Register Supports Privacy Claim

This fixture should pass because each regulatory or framework claim is backed by a current official source with review metadata.

```text
finding: Missing AI privacy risk assessment is High
supported_claim: NIST AI RMF MAP 5.1 requires identifying privacy risk in AI data flows
source_name: NIST AI Risk Management Framework
source_owner: NIST
url: https://www.nist.gov/itl/ai-risk-management-framework
published_effective: January 2023
reviewed_date: 2026-06-05
source_status: Verified
confidence: High
source_register_id: SRC-001
```

```text
finding: De-identification governance needs current official support
supported_claim: SP 800-188 is the official de-identification guidance source for this assessment
source_name: NIST SP 800-188
source_owner: NIST CSRC
url: https://csrc.nist.gov/pubs/sp/800/188/final
published_effective: final publication page
reviewed_date: 2026-06-05
source_status: Verified
confidence: High
source_register_id: SRC-002
```

Expected result: pass. The report records source owner, final official URL, reviewed date, status, supported claim, and confidence before using the source to support a High privacy finding.
