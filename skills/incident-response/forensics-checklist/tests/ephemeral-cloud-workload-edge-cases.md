# Ephemeral Cloud Workload Edge Cases

Use these cases to validate that `forensics-checklist` does not treat cloud snapshots or activity logs as complete forensic evidence for short-lived workloads.

## Case 1: Kubernetes pod evicted before workload evidence capture

**Input**

```yaml
incident: suspicious outbound traffic from checkout pod
cloud_evidence:
  node_snapshot: captured
  cloud_audit_logs: exported
kubernetes:
  pod_name: checkout-7c9f5d6b8c-f2x4q
  pod_status: evicted
  pod_yaml: missing
  pod_events: missing
  current_logs: missing
  previous_logs: missing
  image_digest: missing
  service_account: unknown
  owner_refs: unknown
```

**Expected result**

Fail the evidence completeness check and classify as P1. The node snapshot and provider logs do not preserve pod identity, container runtime state, previous logs, image digest, service account, or controller ownership.

## Case 2: Serverless alias captured without immutable version

**Input**

```yaml
incident: suspicious S3 writes from Lambda function
cloud_evidence:
  cloudtrail: exported
serverless:
  provider: aws
  function_name: invoice-processor
  alias: prod
  function_version: missing
  code_sha256: missing
  runtime_layers: missing
  environment_refs: missing
  execution_role_policy_snapshot: missing
  event_source_mapping: missing
  invocation_logs: partial
```

**Expected result**

Classify as P1 if the incident cannot be tied to an immutable function version or package hash. A mutable alias is not enough to prove what code and configuration executed during the incident window.

## Case 3: Container image tag recorded without digest

**Input**

```yaml
incident: suspicious process in managed container task
managed_container:
  platform: fargate
  service: public-api
  task_definition_revision: captured
  image: registry.example.com/api:latest
  image_digest: missing
  registry_metadata: missing
  command: missing
  environment_refs: partial
  runtime_logs: captured
```

**Expected result**

Classify as P2 or higher depending on impact. The report must identify that `latest` is mutable and request image digest, registry metadata, runtime command, and complete environment or secret references.

## Case 4: Complete ephemeral workload evidence record

**Input**

```yaml
incident: confirmed credential misuse from containerized worker
kubernetes:
  pod_yaml: captured
  pod_events: captured
  current_logs: captured
  previous_logs: captured
  image_digest: sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000
  service_account: worker-prod
  owner_refs: deployment/worker
  network_policy: captured
  audit_events: captured
serverless:
  function_version: "42"
  alias_mapping_at_incident: prod -> 42
  code_sha256: abc123
  layers: captured
  execution_role_policy_snapshot: captured
  event_source_mapping: captured
  invocation_logs: captured
cloud_scope:
  accounts: all affected accounts checked
  regions: all affected regions checked
```

**Expected result**

Pass the ephemeral workload evidence gate. The report should still list any legal, retention, or access limitations, but it has immutable workload identity, logs, runtime configuration, and provider audit context.
