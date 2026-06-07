# Benign: Traceable Internal Audit Program Evidence

This sample should be treated as stronger Clause 9.2 and Clause 10.2 evidence because it includes scope, criteria, sampling, independence, retained evidence, management reporting, and corrective-action closure details.

```yaml
isms_internal_audit:
  audit_program:
    audit_id: IA-2026-AC-01
    objective: verify privileged-access review control effectiveness
    criteria:
      - ISO/IEC 27001:2022 Clause 9.2
      - ISO/IEC 27001:2022 Clause 10.2
      - Annex A.5.15
      - Annex A.5.18
      - access_review_policy_v4
    scope:
      process: quarterly privileged-access review
      systems:
        - production identity provider
        - cloud admin groups
      period: 2026-Q1
    risk_linkage:
      risk_register_ids:
        - RISK-IAM-004
      previous_findings:
        - IA-2025-07
    auditor:
      name: internal audit manager
      independence_evidence:
        conflict_check: no operational ownership for IAM process
        approved_by: risk committee
    sampling:
      population: 184 privileged access assignments
      method: risk-based plus random sample
      selected_samples:
        - IAM-ASSIGN-0102
        - IAM-ASSIGN-0141
        - IAM-ASSIGN-0177
      rationale: all break-glass roles plus 10 percent random sample of standard admin roles
    retained_workpapers:
      location: grc://audits/IA-2026-AC-01/workpapers
      evidence_types:
        - access export
        - reviewer signoff
        - ticket links
        - screenshot bundle
      capture_date: 2026-04-08
    management_reporting:
      date: 2026-04-12
      audience:
        - CISO
        - risk committee
      decisions:
        - accepted corrective action CA-2026-011
    corrective_actions:
      - id: CA-2026-011
        finding: IA-2026-AC-01-F01
        iso_ref: Annex A.5.18
        root_cause: access review evidence owner not assigned for two cloud admin groups
        owner: IAM service owner
        due_date: 2026-05-15
        action_taken: added evidence owner field and monthly reminder workflow
        implementation_evidence: grc://actions/CA-2026-011/implementation
        effectiveness_evidence: 2026-06 sample showed all admin groups had evidence owners
        closure_date: 2026-06-03
        status: closed
```

Expected result:

- Do not raise `ISO-AUDIT-01` through `ISO-AUDIT-07` for this sample.
- Report the audit in the Internal Audit Program Evidence table.
- Report `CA-2026-011` in the Corrective Action Closure Evidence table.
