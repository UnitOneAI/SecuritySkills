---
case: aligned-m365-dmarc-reject
expected: benign
finding_ids: []
---

# Benign: Inventoried Microsoft 365 Sender With Strict DMARC

```dns
example.com. MX 0 example-com.mail.protection.outlook.com.
example.com. TXT "v=spf1 include:spf.protection.outlook.com -all"
selector1._domainkey.example.com. CNAME selector1-example-com._domainkey.example.onmicrosoft.com.
selector2._domainkey.example.com. CNAME selector2-example-com._domainkey.example.onmicrosoft.com.
_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc-aggregate@example.com; adkim=s; aspf=s"
```

```yaml
header_evidence:
  spf_result: pass
  dkim_result: pass
  dmarc_result: pass
  from_domain_aligned: true
reporting:
  aggregate_reports_received: true
  owner: messaging-security
confidence: strong
```

Expected review: pass strict DMARC posture when sender inventory, header alignment, and report monitoring are evidenced.
