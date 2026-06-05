---
case: documented supplier dependency evidence
expected: benign
---

# Documented Supplier Dependency Evidence

The assessment includes operational evidence for a critical supplier dependency:

```yaml
supplier_dependency:
  supplier: primary_cloud_provider
  dependent_service: customer_api
  criticality: critical
  sole_source: false
  viable_substitute: secondary_region_and_provider_runbook
  switching_time: "8 hours"
  tested_failover: "2026-04-18"
  contract_portability:
    data_export: supported
    configuration_export: supported
    license_constraint: none
  residual_impact: degraded_capacity_for_batch_jobs
fourth_party_chain:
  - direct_supplier: primary_cloud_provider
    fourth_party: observability_provider
    service_or_data: platform_metrics
    region: eu
    change_notice: supplier_subprocessor_list
    monitoring_owner: platform_security
exit_evidence:
  identity_revoked: not_applicable_active_supplier
  data_export_tested: "2026-04-18"
  integration_secret_rotation_runbook: present
supplier_incident_participation:
  incident_contact: named_support_manager
  escalation_sla: "1 hour"
  joint_tabletop: "2026-03-22"
  evidence_package_expected:
    - status_page_updates
    - incident_timeline
    - root_cause_summary
```

Expected assessment behaviour:

- Accept GV.OC-05 and GV.SC evidence for this supplier because dependency concentration, substitute feasibility, fourth-party visibility, exit planning, and incident participation are evidenced.
- Keep any remaining supplier rows separate rather than using this evidence to clear unrelated suppliers.
- Retest if the supplier, region, fourth-party list, failover runbook, contract portability, incident contact, or exit process changes.
