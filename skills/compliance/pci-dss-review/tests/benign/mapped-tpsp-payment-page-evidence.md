# Benign: TPSP and payment-page evidence are mapped

```yaml
assessment:
  standard_version: PCI DSS v4.0.1
  source_document: PCI-DSS-v4_0_1.pdf
  review_date: 2026-06-02
  validation_type: SAQ A-EP
  eligibility_evidence: merchant checkout page can affect hosted payment fields
tpsp:
  name: Example PSP
  aoc_date: 2026-03-15
  covered_service: hosted payment fields for the assessed merchant entity
  written_acknowledgment: present
  responsibility_matrix:
    merchant:
      - payment-page script authorization
      - tag-manager governance
    psp:
      - hosted payment field processing
      - PSP-hosted field integrity
payment_page_scripts:
  - source: https://cdn.example-psp.test/fields.js
    controller: PSP
    owner: PSP security
    authorization: PSP AOC and merchant contract
    integrity_control: monitored PSP release channel
    tamper_detection: PSP and merchant alerts
  - source: https://tags.example.test/container.js
    controller: merchant
    owner: ecommerce engineering
    authorization: CHG-2026-0412
    integrity_control: approved tag-manager workflow
    tamper_detection: script inventory delta monitor
```

Expected assessment: this is not automatically compliant, but it has the
required evidence anchors for an assessor-verifiable review. The skill should
avoid false Not Evaluable results when source version, SAQ basis, TPSP
responsibility, authorization, integrity, and tamper-detection evidence are
all mapped.
