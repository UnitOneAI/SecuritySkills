# Benign: payment-page and TPSP evidence are mapped

```yaml
standard:
  version: PCI DSS v4.0.1
  source_document: PCI DSS v4.0.1
  source_document_date: 2024-06-11
validation:
  type: SAQ A-EP
  eligibility_evidence: merchant checkout page can affect PSP-hosted payment iframe
tpsp:
  name: example-psp
  aoc_date: 2026-03-15
  covered_service: hosted payment fields for example merchant entity
  responsibility_matrix: provided
payment_page_scripts:
  - src: https://cdn.example-psp.com/fields.js
    owner: PSP
    authorization: PSP AOC and merchant contract
    business_justification: hosted field rendering
    integrity_control: CSP allowlist plus monitored hash baseline
    change_detection: 11.6.1 monitor alerts to payment-security@example.com
  - src: https://tag.example.com/gtm.js
    owner: merchant
    authorization: change ticket CHG-2026-0402
    business_justification: checkout analytics
    integrity_control: tag-manager approval workflow
    change_detection: script inventory delta alert
```

Expected assessment: this evidence can support an assessor-verifiable result
when mapped to the relevant requirements. Individual controls still need normal
testing, but the report should not fail solely because the checkout uses hosted
fields or merchant-controlled scripts.
