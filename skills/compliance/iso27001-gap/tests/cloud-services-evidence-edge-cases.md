# ISO 27001 Cloud Services Evidence Edge Cases

These fixtures validate that `iso27001-gap` does not mark A.5.23 conforming
from vendor names or certificates alone. The reviewer must prove customer-side
cloud governance, shared responsibility, and exit readiness.

## Edge Case 1: Provider Certificate Without Customer Controls

Input evidence:

```yaml
cloud_service: production_aws_account
supplier_evidence:
  provider: AWS
  iso27001_certificate: current
  soc2_report: current
customer_evidence:
  shared_responsibility_matrix: missing
  cloudtrail_enabled: unknown
  iam_review: missing
  backup_restore_test: missing
```

Expected output:

- Finding ID: `ISO-CLOUD-02` or `ISO-CLOUD-08`
- A.5.23 is not conforming
- Report states that provider assurance does not prove customer-managed controls
- Remediation requires shared responsibility mapping and customer control evidence

## Edge Case 2: SaaS Vendor With Carve-Out Subservice Organizations

Input evidence:

```yaml
cloud_service: customer_support_saas
data_classification: confidential
supplier_evidence:
  soc2_type2_report_date: 2025-01-15
  subservice_method: carve_out
  subservice_organizations:
    - analytics_vendor
    - email_delivery_vendor
customer_evidence:
  subservice_review: missing
  contract_dpa: present
  data_residency_commitment: eu_only
```

Expected output:

- Finding ID: `ISO-CLOUD-03`
- Supplier evidence freshness and scope are recorded
- Carve-out subservice organizations require separate review or compensating evidence
- Data residency commitment is not accepted without contract and configuration evidence

## Edge Case 3: No Exit Test for Critical Cloud Service

Input evidence:

```yaml
cloud_service: identity_provider
criticality: high
contract_notice_period_days: 30
data_export_format: proprietary
exit_plan:
  owner: security_lead
  last_test_date: null
  fallback_provider: null
```

Expected output:

- Finding ID: `ISO-CLOUD-06`
- Severity: Minor Nonconformity or Major Nonconformity depending on criticality and continuity dependence
- Roadmap includes export test, fallback owner, and contract notice tracking
- Linked controls include A.5.23, A.5.29, and A.5.30
