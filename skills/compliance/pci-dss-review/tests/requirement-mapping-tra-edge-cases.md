# PCI Requirement Mapping and TRA Edge Cases

These fixtures verify that `pci-dss-review` does not substitute Requirement 2 evidence across adjacent sub-requirements and keeps 12.3.1 targeted risk analysis separate from 12.3.2 Customized Approach evidence.

```yaml
case_id: PCI-MAP-01
title: Non-console admin encryption cannot satisfy 2.2.5
source:
  version: PCI DSS v4.0.1
  review_date: "2026-06-06"
  requirement_mapping_checked: true
evidence:
  non_console_admin_access:
    ssh: encrypted
    rdp_tls: encrypted
  hardening:
    enabled_services_inventory: missing
    insecure_service_business_justification: missing
    additional_security_features: missing
expected_classification:
  "2.2.5":
    status: Not Evaluable
    reason: "2.2.5 requires insecure-service justification and added security features when insecure services are present."
  "2.2.7":
    status: In Place
    reason: "Non-console administrative access is encrypted using strong cryptography."
```

```yaml
case_id: PCI-MAP-02
title: Insecure Telnet daemon has documented business justification and controls
source:
  version: PCI DSS v4.0.1
  review_date: "2026-06-06"
  requirement_mapping_checked: true
evidence:
  insecure_service:
    protocol: telnet
    business_justification: legacy payment terminal maintenance
    compensating_network_controls:
      - jump_host_required
      - restricted_source_cidr
      - session_recording
    migration_date: "2026-09-30"
expected_classification:
  "2.2.5":
    status: In Place with documented exception
    reason: "Business justification and additional security features are documented."
```

```yaml
case_id: PCI-MAP-03
title: Enabled services inventory proves 2.2.4 but not 2.2.7
source:
  version: PCI DSS v4.0.1
  review_date: "2026-06-06"
  requirement_mapping_checked: true
evidence:
  enabled_services_inventory:
    only_necessary_services: true
  non_console_admin_access:
    encryption_evidence: missing
expected_classification:
  "2.2.4":
    status: In Place
    reason: "Only necessary services, protocols, daemons, and functions are enabled."
  "2.2.7":
    status: Not Evaluable
    reason: "Enabled-service inventory does not prove non-console administrative access encryption."
```

```yaml
case_id: PCI-MAP-04
title: Missing source version blocks In Place status
source:
  version: missing
  source_document: missing
  review_date: missing
  requirement_mapping_checked: false
report_claim:
  result: In Place
  sub_requirement: "2.2.5"
expected_classification:
  status: Needs Source Cross-Check
  reason: "Source document, version, review date, and mapping check must be recorded before any In Place result."
```

```yaml
case_id: PCI-MAP-05
title: Requirement-specified TRA for log review frequency is 12.3.1 evidence
source:
  version: PCI DSS v4.0.1
  requirement_mapping_checked: true
tra:
  requirement: "10.4.2"
  type: requirement_specified_frequency
  threats_considered: true
  likelihood: documented
  impact: documented
  decision: weekly review for non-critical logs
  approver: risk-committee
expected_classification:
  "12.3.1":
    status: In Place
    reason: "TRA defines an entity-specific frequency for a requirement that calls for targeted risk analysis."
  "12.3.2":
    status: Not Applicable
    reason: "No Customized Approach requirement is being claimed."
```

```yaml
case_id: PCI-MAP-06
title: Customized Approach cannot use a frequency TRA alone
source:
  version: PCI DSS v4.0.1
  requirement_mapping_checked: true
customized_approach:
  requirement: "8.3.9"
  objective: present
  controls_matrix: missing
  risk_analysis: frequency_only_tra
  senior_management_approval: missing
  assessor_validation_basis: missing
expected_classification:
  "12.3.2":
    status: Not Evaluable
    reason: "Customized Approach needs controls matrix, risk analysis, senior management approval, and assessor validation evidence."
```

```yaml
case_id: PCI-MAP-07
title: Compensating control worksheet is not Customized Approach TRA evidence
source:
  version: PCI DSS v4.0.1
  requirement_mapping_checked: true
evidence:
  compensating_control_worksheet:
    original_requirement: "2.2.5"
    constraint: documented
    compensating_control: documented
  customized_approach_tra:
    controls_matrix: missing
    senior_management_approval: missing
expected_classification:
  compensating_control:
    status: Review separately
    reason: "CCWs and Customized Approach TRAs are separate evidence models."
  "12.3.2":
    status: Not Evaluable
    reason: "A CCW does not replace Customized Approach TRA evidence."
```
