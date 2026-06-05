---
case: monitored-dmarc-rollout-pnone
expected: benign
finding_ids: []
---

# Benign: Monitored DMARC Rollout in p=none

```dns
example.org. TXT "v=spf1 include:_spf.google.com include:sendgrid.net -all"
_dmarc.example.org. TXT "v=DMARC1; p=none; rua=mailto:dmarc-aggregate@example.org; adkim=r; aspf=r"
```

```yaml
rollout_state:
  owner: messaging-security
  aggregate_reports_received: true
  unknown_sources_triaged: weekly
  aligned_senders_percent: 96
  target_policy: quarantine
  target_date: 2026-07-15
  open_sender_backlog:
    - ticket: MAIL-1842
      sender: billing-saas
      issue: DKIM alignment pending
confidence: partial
```

Expected review: do not escalate solely because policy is `p=none`; record as controlled rollout if reports, owner, backlog, and enforcement plan are present.
