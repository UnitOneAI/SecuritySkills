---
case: stale-mta-sts-policy
expected: vulnerable
finding_ids:
  - EMAIL-TLS-01
  - EMAIL-TLS-02
  - EMAIL-TLS-03
---

# Vulnerable: Stale MTA-STS Policy

```dns
example.com. MX 10 mx1.current-mail.example.
_mta-sts.example.com. TXT "v=STSv1; id=2026060101"
```

```txt
https://mta-sts.example.com/.well-known/mta-sts.txt

version: STSv1
mode: enforce
mx: mx1.old-mail.example
max_age: 604800
```

```yaml
tls_rpt_record: missing
mx_matches_policy: false
rollback_plan: unknown
```

Expected review: flag stale MX policy in enforce mode, especially when TLS-RPT is missing and rollback evidence is unknown.
