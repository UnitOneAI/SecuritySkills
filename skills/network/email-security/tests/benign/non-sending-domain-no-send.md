---
case: non-sending-domain-no-send
expected: benign
finding_ids: []
---

# Benign: Non-Sending Domain With Explicit No-Send Posture

```dns
example.net. MX 0 .
example.net. TXT "v=spf1 -all"
_dmarc.example.net. TXT "v=DMARC1; p=reject"
```

```yaml
classification: non-sending
owner: brand-protection
last_review: 2026-06-01
header_evidence_required: false
confidence: strong
```

Expected review: do not require DKIM or sender headers for a confirmed non-sending domain with null MX, SPF fail-all, DMARC reject, and owner evidence.
