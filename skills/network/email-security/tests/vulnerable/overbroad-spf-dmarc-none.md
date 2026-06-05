---
case: overbroad-spf-dmarc-none
expected: vulnerable
finding_ids:
  - EMAIL-INV-01
  - EMAIL-SPF-02
  - EMAIL-DMARC-02
  - EMAIL-DMARC-04
---

# Vulnerable: Overbroad SPF and Unmonitored DMARC

```dns
example.com. TXT "v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org include:spf.protection.outlook.com include:_spf.salesforce.com ~all"
_dmarc.example.com. TXT "v=DMARC1; p=none"
```

Expected review: require sender inventory, SPF include ownership, aggregate reporting, owner, report review cadence, and an enforcement plan before treating this as controlled.
