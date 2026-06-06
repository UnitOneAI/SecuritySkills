# Serverless Identity, Secrets, Eventarc, and Resource-Limit Edge Cases

These fixtures calibrate the supplemental `gcp-review` serverless evidence gate. Reviewers should evaluate Cloud Run / Cloud Functions v2 public access, runtime identity, Secret Manager usage, Eventarc trigger reachability, Workload Identity Federation, and concurrency/resource limits together.

## Vulnerable: Public Cloud Run Admin API With Literal Secret and Weak Limits

```yaml
case: cloud-run-public-admin-literal-secret
resource: google_cloud_run_v2_service.admin_api
evidence:
  ingress: INGRESS_TRAFFIC_ALL
  invoker_iam:
    role: roles/run.invoker
    member: allUsers
  runtime_service_account: default-compute@example.iam.gserviceaccount.com
  env:
    ADMIN_API_TOKEN:
      type: literal
      value: plain-text-token
  resource_limits:
    max_instance_request_concurrency: 1000
    timeout: 3600s
    max_instance_count: missing
expected_result:
  decision: Fail
  severity: Critical
  reason: Public unauthenticated admin API combines literal secret exposure, default runtime identity, high concurrency, long timeout, and no max instance cap.
  required_evidence: Record public invoker, ingress, runtime service account, secret source, concurrency, timeout, and scaling limit findings.
```

## Vulnerable: Cloud Functions v2 Literal Secret and Broad Eventarc Source

```yaml
case: functions-v2-eventarc-broad-source
resource: google_cloudfunctions2_function.webhook
evidence:
  service_config:
    environment_variables:
      STRIPE_WEBHOOK_SECRET: whsec_plaintext_value
    service_account_email: default-compute@example.iam.gserviceaccount.com
  event_trigger:
    trigger_region: us-central1
    event_type: google.cloud.storage.object.v1.finalized
    event_filters:
      bucket: missing
    trigger_service_account: missing
  destination: cloud-run-managed-function
expected_result:
  decision: Fail
  severity: High
  reason: Functions v2 uses Cloud Run/Eventarc semantics; literal secret, default service account, missing trigger service account, and missing source bucket filter should be caught.
  required_evidence: Review service_config env vars, runtime service account, Eventarc filters, trigger identity, and source resource ACLs.
```

## Vulnerable: Secret Manager Reference With Broad Access and latest Version

```yaml
case: secret-manager-latest-broad-access
resource: google_cloud_run_v2_service.worker
evidence:
  env:
    PAYMENT_API_KEY:
      type: secret_key_ref
      secret: payment-api-key
      version: latest
  secret_iam:
    role: roles/secretmanager.secretAccessor
    member: allAuthenticatedUsers
  runtime_service_account: checkout-runtime@example.iam.gserviceaccount.com
expected_result:
  decision: Fail
  severity: High
  reason: Secret Manager reference avoids plaintext but uses latest and grants broad accessor rights.
  required_evidence: Distinguish Secret Manager reference from literal secret, then flag unpinned version and broad secretAccessor IAM.
```

## Vulnerable: Workload Identity Federation Without Attribute Conditions

```yaml
case: gcp-wif-missing-conditions
resource: google_iam_workload_identity_pool_provider.github
evidence:
  issuer_uri: https://token.actions.githubusercontent.com
  attribute_mapping:
    google.subject: assertion.sub
    attribute.repository: assertion.repository
  attribute_condition: missing
  impersonation_binding:
    role: roles/iam.workloadIdentityUser
    member: principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/cicd/*
expected_result:
  decision: Fail
  severity: High
  reason: Keyless federation replaces service account keys but over-trusts the shared GitHub issuer without repository/ref conditions and has broad impersonation scope.
  required_evidence: Record issuer, mapping, attribute_condition, and service-account impersonation binding scope.
```

## Vulnerable: Missing Evidence for Disabled Invoker IAM Check

```yaml
case: cloud-run-invoker-check-not-evaluable
resource: google_cloud_run_v2_service.partner_callback
evidence:
  ingress: INGRESS_TRAFFIC_ALL
  invoker_iam_bindings: none_in_iac
  platform_export:
    invoker_iam_check: unavailable
  authentication_expectation: partner-signed-callback
expected_result:
  decision: Not Evaluable
  severity: Medium
  reason: Absence of IAM bindings in IaC does not prove the service is private when Invoker IAM check status and platform export are unavailable.
  required_evidence: Obtain Cloud Run service IAM policy or platform export showing whether Invoker IAM checks are enforced or disabled.
```

## Benign: Private Checkout API With Scoped Secret, WIF, and Bounded Runtime

```yaml
case: private-checkout-api-scoped-secret-wif
resource: google_cloud_run_v2_service.checkout_api
evidence:
  ingress: INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER
  invoker_iam:
    role: roles/run.invoker
    member: serviceAccount:edge-proxy@example.iam.gserviceaccount.com
  runtime_service_account: checkout-runtime@example.iam.gserviceaccount.com
  env:
    PAYMENT_API_KEY:
      type: secret_key_ref
      secret: payment-api-key
      version: "2"
  secret_iam:
    role: roles/secretmanager.secretAccessor
    member: serviceAccount:checkout-runtime@example.iam.gserviceaccount.com
  resource_limits:
    max_instance_request_concurrency: 80
    timeout: 60s
    max_instance_count: 20
  workload_identity_federation:
    issuer_uri: https://token.actions.githubusercontent.com
    attribute_mapping:
      google.subject: assertion.sub
      attribute.repository: assertion.repository
      attribute.ref: assertion.ref
    attribute_condition: attribute.repository == 'example/checkout-api' && attribute.ref == 'refs/heads/main'
expected_result:
  decision: Pass
  severity: Informational
  reason: Private ingress, named invoker, scoped runtime identity, pinned Secret Manager reference, bounded runtime, and constrained WIF evidence are all present.
  required_evidence: Populate the supplemental serverless matrix with pass evidence rather than flagging the secret-looking environment variable name.
```
