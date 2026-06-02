# Vulnerable: SAQ claim lacks payment-page script controls

```yaml
assessment:
  standard_version: PCI DSS v4.0.1
  validation_type: SAQ A
  payment_flow: merchant checkout page embeds hosted PSP fields
merchant_page:
  scripts:
    - https://tags.example.net/container.js
    - https://analytics.example.net/checkout.js
    - https://chat.example.net/widget.js
evidence:
  psp_aoc: present
  saq_eligibility_mapping: missing
  psp_responsibility_matrix: missing
  script_inventory: missing
  script_authorization: missing
  script_integrity_control: missing
  payment_page_tamper_detection: missing
```

Expected assessment: do not mark SAQ eligibility, Req 6.4.3, or Req 11.6.1
as In Place from the PSP AOC alone. Missing merchant-page script governance
and TPSP responsibility mapping should produce Not Evaluable evidence gaps.
