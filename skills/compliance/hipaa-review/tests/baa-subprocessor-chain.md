# HIPAA BAA and Subprocessor Chain Calibration

Use these samples to calibrate BAA, downstream subprocessor, and termination evidence checks for `hipaa-review`.

---

## Should Trigger: Downstream Analytics Processor Not Covered

```yaml
vendor:
  name: CareOps Portal
  role: SaaS scheduling and care-management platform
  ephi_processed:
    - patient_name
    - appointment_reason
    - insurance_member_id
  baa:
    agreement_id: BAA-2026-0042
    signed_at: "2026-02-15"
    covered_services:
      - care-management-portal
  subprocessors:
    - name: MetricsSpark Analytics
      role: product analytics event pipeline
      ephi_seen:
        - appointment_reason
        - insurance_member_id
      listed_in_annex: false
      downstream_baa_or_flowdown: false
      change_notice: null
```

Expected finding:

- **Status:** Fail
- **Classification:** Non-Compliance
- **Reason:** The primary vendor BAA does not prove that the downstream analytics processor handling ePHI is listed, covered by flow-down restrictions, or subject to change-notice/opt-out handling.

---

## Should Not Trigger: Master BAA Covers Actual Managed Database Service

```yaml
vendor:
  legal_entity: Example Cloud Services LLC
  parent_agreement: Master Services Agreement MSA-2025-0088
  baa:
    agreement_id: BAA-2025-0088
    effective_at: "<current BAA effective date RFC3339>"
    renewal_status: current
  service_schedule:
    schedule_id: "<current covered-services schedule>"
    covered_services:
      - managed-postgresql-prod
    covered_regions:
      - us-east-1
      - us-west-2
    tenant_id: ce-prod-123
  ephi_data_flow:
    source: EHR integration service
    destination: managed-postgresql-prod
    region: us-east-1
    data_classes:
      - patient_demographics
      - lab_order_status
  subprocessors:
    annex_version: "<current quarter annex>"
    last_reviewed_at: "<last-review RFC3339>"
    change_notice_days: 30
    region_list_reviewed: true
  termination:
    return_destroy_procedure: documented
    retained_backup_protections: "BAA protections remain until backup expiry"
    backup_expiry: "<termination + 35d RFC3339>"
```

Expected handling:

- **Status:** Pass
- **Reason:** A separate product-level BAA artifact is not required because the master BAA, service schedule, covered service/SKU, region, tenant evidence, subprocessor annex, and termination protections bind the actual ePHI processor.

---

## Should Trigger: Termination Omits Backups, Logs, and Support Exports

```yaml
vendor:
  name: Claims Support Desk
  role: support ticketing for claims application
  baa:
    agreement_id: BAA-2024-0199
    status: terminated
    terminated_at: "<termination date RFC3339>"
  offboarding:
    app_database_deleted_at: "<termination + 3d RFC3339>"
    backups:
      retention_days: 180
      return_or_destroy_evidence: null
    logs:
      contains_ephi: true
      retained_days: 365
      residual_baa_protections: null
    support_exports:
      attachments_contain_ephi: true
      deletion_receipts: []
```

Expected finding:

- **Status:** Fail
- **Classification:** Non-Compliance
- **Reason:** Deleting the primary application database does not prove termination/offboarding is complete when ePHI remains in backups, logs, and support exports without return/destroy evidence, infeasibility rationale, or residual BAA protections.
