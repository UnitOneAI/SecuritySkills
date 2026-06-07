# Vulnerable: Internal Audit Calendar Without Audit Evidence

This sample should be treated as weak Clause 9.2 evidence, not as an audit-ready internal audit program.

```yaml
isms_internal_audit:
  audit_program:
    schedule:
      - quarter: Q1
        area: access control policy
      - quarter: Q2
        area: supplier contracts
      - quarter: Q3
        area: incident response procedure
      - quarter: Q4
        area: backup procedure
    auditor:
      name: CISO
      role: ISMS owner
    retained_evidence:
      - annual calendar invite
      - final summary slide
    management_reporting:
      status: summary emailed
```

Expected findings:

- `ISO-AUDIT-01`: no risk-based frequency or prior-finding rationale.
- `ISO-AUDIT-02`: audit criteria and scope are not defined per engagement.
- `ISO-AUDIT-03`: the ISMS owner audits their own work without independence evidence.
- `ISO-AUDIT-04`: sample population, sample method, and selected samples are missing.
- `ISO-AUDIT-05`: retained evidence is only a summary, not reproducible workpapers.
- `ISO-AUDIT-07`: no corrective action owner, root cause, implementation evidence, or effectiveness check.
