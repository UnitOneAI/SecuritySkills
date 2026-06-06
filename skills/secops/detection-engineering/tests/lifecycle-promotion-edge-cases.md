# Detection Lifecycle Promotion Edge Cases

These fixtures verify that detection-engineering ties Sigma status and ATT&CK heatmap scores to lifecycle evidence, backend conversion, field coverage, deployment scope, and false-positive health.

```yaml
case_id: DET-LIFECYCLE-01
title: Stable Sigma status blocked by missing production field coverage
rule:
  title: Suspicious PowerShell Encoded Command Execution
  status: stable
  logsource:
    product: windows
    category: process_creation
  required_fields:
    - Image
    - CommandLine
production_field_coverage:
  Image: present
  CommandLine: unknown
backend_conversion:
  target: splunk
  tested: false
validation:
  last_true_positive_test: null
expected_decision:
  promotion_decision: Hold
  max_coverage_level: Theoretical
  reason: "Stable status lacks field coverage, conversion, and validation evidence."
```

```yaml
case_id: DET-LIFECYCLE-02
title: Synthetic validation permits test status but not operational coverage
rule:
  title: Encoded PowerShell
  status: test
validation:
  method: Atomic Red Team T1059.001
  date: "2026-06-05"
  sample_event_ids:
    - lab-sysmon-001
backend_conversion:
  target: Microsoft Sentinel
  version: pySigma-0.11.14
  result: success
deployment:
  production_enabled: false
expected_decision:
  promotion_decision: Hold
  coverage_level: Tested
  reason: "Synthetic validation and conversion passed, but production deployment is not proven."
```

```yaml
case_id: DET-LIFECYCLE-03
title: Server-only deployment must not score global workstation coverage
technique: T1059.001
coverage_claim:
  requested_level: Operational
  claimed_population: all_windows
deployment:
  included_segments:
    - windows_servers
  excluded_segments:
    - VDI
    - developer_workstations
field_mapping:
  CommandLine:
    windows_servers: present
    developer_workstations: missing
expected_decision:
  server_segment_level: Operational
  workstation_segment_level: None
  score_cap_reason: "Coverage is operational only for servers."
```

```yaml
case_id: DET-LIFECYCLE-04
title: Backend conversion loses Sigma condition semantics
rule:
  title: Suspicious Registry Run Key Modification
  status: test
sigma_condition: selection and not 1 of filter_*
backend_conversion:
  target: QRadar
  result: success_with_warning
  warning: "Wildcard filter list not translated"
validation:
  true_positive_replay: pass
  false_positive_filter_test: fail
expected_decision:
  promotion_decision: Hold
  max_coverage_level: Tested
  reason: "Conversion fidelity is incomplete and FP filter semantics are lost."
```

```yaml
case_id: DET-LIFECYCLE-05
title: Stable rule should be demoted when false-positive budget is exceeded
rule:
  title: Suspicious Service Creation
  status: stable
false_positive_health:
  budget_per_day: 5
  observed_per_day: 86
  last_review: "2026-06-04"
deployment:
  production_enabled: true
owner: detection-engineering
demotion_criteria:
  fp_budget_exceeded: true
expected_decision:
  promotion_decision: Demote
  new_status: test
  reason: "Rule health no longer supports stable operational coverage."
```

```yaml
case_id: DET-LIFECYCLE-06
title: Robust coverage requires complementary rules and real-world/replay evidence
technique: T1059.001
coverage_claim:
  requested_level: Robust
rules:
  - id: powershell_encoded_command
    status: stable
    catches_real_world_activity: true
  - id: powershell_download_cradle
    status: stable
    replay_validated: true
  - id: powershell_amsi_bypass
    status: test
    replay_validated: true
telemetry_scope:
  windows_servers: present
  windows_workstations: present
false_positive_health:
  within_budget: true
expected_decision:
  coverage_level: Robust
  reason: "Complementary stable/tested rules cover multiple procedure examples with production telemetry and FP health."
```

```yaml
case_id: DET-LIFECYCLE-07
title: Missing owner and review cadence blocks stable promotion
rule:
  title: Suspicious CloudTrail Console Login
  status: test
validation:
  date: "2026-06-05"
  method: replayed_cloudtrail_fixture
backend_conversion:
  target: Chronicle
  result: success
field_mapping:
  userAgent: present
  sourceIPAddress: present
owner: null
review_cadence: null
demotion_criteria: null
expected_decision:
  promotion_decision: Hold
  max_coverage_level: Tested
  reason: "Lifecycle ownership and demotion criteria are required before stable status."
```
