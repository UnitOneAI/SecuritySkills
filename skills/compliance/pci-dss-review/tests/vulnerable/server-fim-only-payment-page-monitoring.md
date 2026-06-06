# Vulnerable Evidence: Server FIM Only

- Requirement claimed: PCI DSS 11.6.1
- Evidence provided: repository file integrity monitoring is enabled for `/templates/checkout.html`.
- Missing evidence: no browser-received payment-page snapshot, no HTTP header comparison, no script/iframe addition alerting, and no monitor mapped to CDN or tag-manager changes.
- Result: incomplete for 11.6.1 because consumer-browser received headers and page content are not evaluated.
