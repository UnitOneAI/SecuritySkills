# Benign Evidence: Browser-Received Payment Page Monitoring

- Requirement: PCI DSS 11.6.1
- Payment-page URLs monitored: `/checkout`, `/pay`, `/payment/confirm`
- Mechanism: headless browser renders each page and compares received HTTP headers, script inventory, iframe list, forms, and CSP.
- Frequency: every 7 days and after payment-page deployments.
- Alerts: unauthorized script additions, script deletions, CSP/header changes, and payment-form DOM changes page SecOps.
- Scope linkage: monitored URL inventory matches the 6.4.3 script inventory.
