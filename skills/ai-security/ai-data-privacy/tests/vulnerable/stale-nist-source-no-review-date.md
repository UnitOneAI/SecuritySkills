# Vulnerable: Stale NIST URLs Are Used Without Source Currency Evidence

This fixture should fail because official-looking references are stale and the report does not prove they were checked during the assessment.

```text
finding: Missing AI privacy risk assessment is High
regulatory_reference: NIST AI RMF / NIST SP 800-188
nist_ai_rmf_url: https://www.nist.gov/aiframework
sp_800_188_url: https://csrc.nist.gov/publications/detail/sp/800-188/final
reviewed_date: not recorded
source_status: not checked
supported_claim: AI privacy risk mapping and de-identification governance
confidence: not recorded
```

Expected result: fail. The skill should require the current official AI RMF URL, the stable CSRC publication page, reviewed date, source status, supported claim, and confidence before treating the claim as evaluable.
