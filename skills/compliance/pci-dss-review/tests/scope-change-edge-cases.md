# PCI Scope Change Edge Cases

These fixtures validate PCI DSS v4.0 review behavior for significant-change scope impact analysis under Req 12.5.3.

## Case 1: New Serverless Payment Flow After Annual Review

```yaml
annual_scope_review:
  completed: "2026-01-15"
change:
  id: CHG-101
  deployed: "2026-04-10"
  component: payment-webhook-lambda
  handles:
    - payment_token
    - transaction_metadata
  pci_scope_impact_review: missing
  cde_diagram_updated: false
```

**Expected result:** High severity finding.

**Reason:** A new payment flow was deployed after annual scope confirmation without change-specific PCI scope impact evidence.

## Case 2: Segmentation Change Without Revalidation

```yaml
change:
  id: CHG-202
  type: firewall_rule_update
  affects:
    - cde_to_corp_network
    - admin_vpn_to_cde
  segmentation_validation:
    updated_pen_test: false
    route_review: partial
    security_owner_approval: true
```

**Expected result:** High severity finding.

**Reason:** Segmentation-affecting changes require refreshed validation evidence; approval alone does not prove segmentation remains effective.

## Case 3: TPSP Responsibility Changed

```yaml
provider_change:
  id: CHG-303
  provider: fraud-analytics-saas
  new_data_access:
    - transaction_id
    - masked_pan
  tpsp_inventory_updated: false
  responsibility_matrix_updated: false
  aoc_reviewed: false
```

**Expected result:** High severity finding.

**Reason:** Provider responsibility and data access changed, but the TPSP inventory, responsibility matrix, and compliance evidence were not refreshed.

## Case 4: Complete Scope Impact Evidence

```yaml
scope_change_impact:
  change_id: CHG-404
  trigger: new_payment_api
  owner: pci-program-manager
  reviewed_before_release: true
  data_flow_update:
    chd_sad_flow_changed: true
    diagram_version: cde-flow-v18
  scope_inventory:
    cde_components_added:
      - payment-api
    connected_to_systems_added:
      - auth-service
      - siem-forwarder
  segmentation:
    affected: true
    validation_evidence: seg-test-2026-06-01
  tpsp:
    affected: true
    responsibility_matrix_version: tpsp-raci-v9
    aoc_status_reviewed: true
  evidence_refresh:
    requirements:
      - "1"
      - "6"
      - "10"
      - "11"
      - "12"
  approvals:
    security_owner: approved
    business_owner: approved
    pci_owner: approved
```

**Expected result:** Pass for Req 12.5.3 evidence if implementation evidence matches the record.

**Reason:** The change is explicitly tied to scope, data-flow, segmentation, TPSP, evidence refresh, and owner approval artifacts.

## Review Assertions

- Do not accept annual scope confirmation as proof of mid-cycle change review.
- Confirm payment, network, cloud, TPSP, and security-impacting changes trigger PCI scope impact analysis.
- Confirm segmentation changes refresh validation evidence.
- Confirm scope reduction claims are updated after architecture changes.
