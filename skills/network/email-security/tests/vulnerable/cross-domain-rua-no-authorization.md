---
case: cross-domain-rua-no-authorization
expected: vulnerable
finding_ids:
  - EMAIL-DMARC-05
  - EMAIL-RPT-02
---

# Vulnerable: Cross-Domain DMARC Reporting Without Authorization Evidence

```dns
_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@vendor.example"
```

```yaml
report_authorization:
  destination_domain: vendor.example
  authorization_record_found: false
  report_owner: unknown
  last_review: unknown
```

Expected review: do not fail strict DMARC policy only because the report destination is external, but require external reporting authorization and report ownership evidence.
