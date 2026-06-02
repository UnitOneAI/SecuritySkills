# Vulnerable: SAQ A claim without payment-page script evidence

```yaml
merchant_profile:
  channel: card-not-present ecommerce
  validation_claim: SAQ A
  payment_integration: hosted PSP checkout with merchant page scripts
  merchant_checkout_page_controls:
    tag_manager: enabled
    analytics_scripts: enabled
    chat_widget: enabled
pci_evidence:
  psp_aoc: current
  psp_responsibility_matrix: missing
  saq_eligibility_mapping: missing
  payment_page_script_inventory: missing
  script_authorization_records: missing
  script_integrity_evidence: missing
  payment_page_change_detection: missing
```

Expected assessment: do not mark the SAQ selection or payment-page
requirements as validated from the PSP AOC alone. Missing SAQ eligibility,
responsibility split, and Req 6.4.3/11.6.1 script evidence should produce a
Not Evaluable or Not in Place result, depending on the assessment scope.
