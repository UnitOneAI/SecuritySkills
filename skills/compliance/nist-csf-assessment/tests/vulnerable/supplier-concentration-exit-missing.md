---
case: supplier concentration and exit evidence missing
expected: vulnerable
---

# Supplier Concentration And Exit Evidence Missing

An assessment scores GV.SC as repeatable because the supplier inventory and contracts are complete:

```yaml
critical_service: customer_identity
primary_supplier: identity_saas_a
supplier_inventory: present
security_addendum: present
breach_notice_clause: present
claimed_gv_sc_score: 3
missing_evidence:
  sole_source_status: unknown
  viable_substitute: none
  tested_failover: false
  switching_time: unknown
  fourth_party_chain: missing
  supplier_incident_contact: missing
  joint_tabletop: not_tested
```

A second supplier was terminated, but offboarding evidence stops at procurement closure:

```yaml
supplier: support_saas_b
relationship_ended: "2026-05-31"
final_invoice_paid: true
missing_exit_evidence:
  sso_app_disabled: unknown
  api_tokens_revoked: unknown
  webhook_secrets_rotated: false
  vendor_subdomain_removed: unknown
  data_deletion_certificate: missing
  support_attachments_retention: unknown
```

Expected assessment behaviour:

- Reject the mature GV.SC score because inventory and contract evidence do not prove substitutability, fourth-party visibility, incident readiness, or exit completion.
- Mark GV.OC-05, GV.SC-04, GV.SC-07, GV.SC-08, GV.SC-09, and GV.SC-10 as gaps or not evaluable according to the missing evidence owner.
- Require supplier concentration, fourth-party, exit, and incident participation tables before accepting repeatable maturity.
