# Platform and Logsource Compatibility Fixtures

These fixtures calibrate the supplemental `DE-PLATFORM-*` evidence gates in `detection-engineering`.

```yaml
case: linux_shell_detection_with_auditd_mapping
request:
  technique: T1059.004
  target_platform: linux
  intended_detection: Unix shell execution
telemetry:
  required:
    - process_creation
    - command_execution
  actual_log_source: auditd execve
sigma:
  logsource:
    product: linux
    category: process_creation
  field_mapping:
    process_path: exe
    command_line: cmdline
    user: auid
    parent_process: ppid
backend:
  target: splunk
  conversion_supported: true
validation:
  method: replayed_auditd_execve_fixture
  negative_control: benign_shell_admin_script
blind_spots:
  - shell_builtins_without_execve
  - truncated_command_line
expected_decision: Pass
expected_findings: []
```

```yaml
case: linux_request_gets_windows_process_rule
request:
  technique: T1059.004
  target_platform: linux
  intended_detection: Unix shell execution
telemetry:
  actual_log_source: auditd execve
incorrect_output:
  sigma_logsource:
    product: windows
    category: process_creation
  fields:
    - Image
    - CommandLine
    - ParentImage
  validation: Atomic Red Team T1059.001 Windows PowerShell test
expected_decision: Fail
expected_findings:
  - check: DE-PLATFORM-03
    severity: High
    reason: Linux target is expressed with Windows process_creation logsource.
  - check: DE-PLATFORM-04
    severity: High
    reason: Windows field names are used without a backend normalization mapping from auditd.
  - check: DE-PLATFORM-06
    severity: Medium
    reason: Validation method does not match the requested Linux sub-technique.
```

```yaml
case: macos_applescript_endpointsecurity_complete
request:
  technique: T1059.002
  target_platform: macos
  intended_detection: AppleScript execution
telemetry:
  actual_log_sources:
    - EndpointSecurity process events
    - osquery process_events
sigma:
  logsource:
    product: macos
    category: process_creation
  field_mapping:
    process_path: process.path
    command_line: process.command_line
    parent_process: process.parent.path
    signing_identity: process.code_signature.signing_id
backend:
  target: elastic
  conversion_supported: true
validation:
  method: replayed_osascript_execution_fixture
  negative_control: signed_it_automation
blind_spots:
  - unified_log_message_not_collected
  - osquery_schedule_latency
expected_decision: Pass
expected_findings: []
```

```yaml
case: aws_cloudtrail_valid_accounts_complete
request:
  technique: T1078
  target_platform: aws
  intended_detection: suspicious IAM credential use
telemetry:
  actual_log_source: CloudTrail management events
  organization_trail: enabled
  regions: all_enabled_regions
sigma:
  logsource:
    product: aws
    service: cloudtrail
  field_mapping:
    event_name: eventName
    identity_type: userIdentity.type
    source_ip: sourceIPAddress
    mfa_used: additionalEventData.MFAUsed
    recipient_account: recipientAccountId
backend:
  target: sentinel
  conversion_supported: native_kql_fallback_documented
validation:
  method: sandbox_iam_api_call_and_replayed_cloudtrail_fixture
blind_spots:
  - organization_trail_delivery_delay
  - unsupported_service_data_events_not_enabled
expected_decision: Pass
expected_findings: []
```

```yaml
case: cloud_control_plane_detection_as_endpoint_process
request:
  technique: T1078
  target_platform: aws
  intended_detection: valid account abuse
telemetry:
  actual_log_source: CloudTrail management events
incorrect_output:
  sigma_logsource:
    product: windows
    category: process_creation
  fields:
    - Image
    - CommandLine
    - ParentImage
  validation: run Atomic Red Team endpoint process test
expected_decision: Fail
expected_findings:
  - check: DE-PLATFORM-02
    severity: High
    reason: Required cloud audit telemetry is not represented in the detection output.
  - check: DE-PLATFORM-03
    severity: High
    reason: AWS control-plane behavior is modeled as endpoint process creation.
  - check: DE-PLATFORM-06
    severity: Medium
    reason: Endpoint validation does not prove CloudTrail coverage.
```

```yaml
case: multi_platform_command_interpreter_matrix
request:
  technique: T1059
  target_platform: multi-platform
coverage_matrix:
  windows:
    logsource:
      product: windows
      category: process_creation
    field_mapping: complete
    validation: Atomic Red Team T1059.001
    status: deployable
  linux:
    logsource:
      product: linux
      category: process_creation
    field_mapping: complete
    validation: auditd fixture
    status: deployable
  macos:
    logsource:
      product: macos
      category: process_creation
    field_mapping: missing_signing_identity
    validation: missing
    status: Not Evaluable
expected_decision: Partial
expected_findings:
  - check: DE-PLATFORM-07
    severity: Medium
    reason: Multi-platform output records deployable Windows/Linux coverage and a Not Evaluable macOS gap instead of claiming universal coverage.
```

```yaml
case: unknown_platform_context
request:
  technique: T1059
  target_platform: unknown
telemetry:
  actual_log_source: missing
backend:
  target: unknown
validation:
  method: missing
expected_decision: Not Evaluable
expected_findings:
  - check: DE-PLATFORM-01
    severity: Medium
    reason: Target platform is unknown and should not silently inherit Windows assumptions.
  - check: DE-PLATFORM-02
    severity: Medium
    reason: Required telemetry cannot be mapped without actual log source evidence.
  - check: DE-PLATFORM-05
    severity: Medium
    reason: Backend support cannot be proven without a target SIEM or native query path.
```
