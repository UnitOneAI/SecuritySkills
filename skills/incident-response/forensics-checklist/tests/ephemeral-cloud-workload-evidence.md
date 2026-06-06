# Ephemeral Cloud Workload Evidence Fixtures

These fixtures calibrate the ephemeral workload evidence gate in `SKILL.md`.

```yaml
case: evicted-kubernetes-pod-missing-runtime-state
workload_type: kubernetes_pod
snapshot_evidence:
  node_disk_snapshot: captured
  provider_audit_logs: exported
workload_evidence:
  pod_yaml: missing
  pod_uid: missing
  namespace: prod
  owner_references: missing
  service_account: missing
  node: missing
  current_logs: missing
  previous_logs: missing
  events: missing
  container_statuses: missing
  image_digest: missing
expected_decision: Fail
expected_findings:
  - check: FORENSICS-EPHEMERAL-01
    severity: Critical
    reason: Pod was evicted before runtime identity and state were preserved.
  - check: FORENSICS-EPHEMERAL-02
    severity: High
    reason: Current and previous container logs are unavailable.
  - check: FORENSICS-EPHEMERAL-06
    severity: High
    reason: Report relies on disk snapshot and provider audit logs for an ephemeral workload.
```

```yaml
case: kubernetes-pod-complete-preservation
workload_type: kubernetes_pod
workload_evidence:
  pod_yaml: captured
  pod_uid: 4a7f2d3e-1111-2222-3333-444455556666
  namespace: prod
  owner_references: captured
  labels_annotations: captured
  service_account: api-reader
  node: ip-10-0-1-23
  current_logs: hashed_export
  previous_logs: hashed_export
  events: captured
  container_statuses: captured
  image_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  mounted_volumes: captured
  network_policy: captured
  kubernetes_audit_events: captured
expected_decision: Pass
expected_findings: []
```

```yaml
case: lambda-prod-alias-only
workload_type: serverless_function
workload_evidence:
  provider: aws_lambda
  function_name: payment-handler
  alias: prod
  immutable_version: missing
  deployment_package_hash: missing
  runtime_layers: missing
  environment_secret_refs: missing
  execution_role: captured
  trigger_mapping: partial
  invocation_logs: captured
  deployment_history: missing
expected_decision: Fail
expected_findings:
  - check: FORENSICS-EPHEMERAL-04
    severity: High
    reason: Mutable alias is preserved without immutable function version and package hash.
```

```yaml
case: cloud-run-revision-complete
workload_type: managed_container_service
workload_evidence:
  provider: cloud_run
  service: invoice-api
  revision: invoice-api-00042-ktr
  image_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  runtime_command: captured
  environment_secret_refs: captured
  service_account: invoice-runtime
  network_attachment: captured
  deployment_history: captured
  invocation_logs: hashed_export
  audit_events: captured
  registry_pull_metadata: captured
expected_decision: Pass
expected_findings: []
```

```yaml
case: ecs-task-latest-tag
workload_type: managed_container_service
workload_evidence:
  provider: ecs_fargate
  cluster: prod
  service: checkout
  task_revision: captured
  image_tag: latest
  image_digest: missing
  runtime_command: partial
  environment_secret_refs: captured
  task_role: captured
  network_attachment: captured
  deployment_history: partial
  logs: captured
expected_decision: Partial
expected_findings:
  - check: FORENSICS-EPHEMERAL-03
    severity: High
    reason: Runtime evidence relies on a mutable image tag without immutable digest.
```

```yaml
case: ephemeral-runner-not-evaluable
workload_type: build_runtime_worker
workload_evidence:
  job_id: captured
  runner_image_digest: missing
  workflow_revision: captured
  checkout_commit: captured
  secrets_boundary: missing
  artifact_digest: captured
  logs: expired
  ephemeral_vm_metadata: missing
missing_reason: provider log retention expired before preservation
expected_decision: Not Evaluable
expected_findings:
  - check: FORENSICS-EPHEMERAL-07
    severity: Medium
    reason: Required runtime worker evidence is unavailable and must be reported with retention and expiry details.
```
