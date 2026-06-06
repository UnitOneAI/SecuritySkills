# Lambda Function URL and Invocation Evidence Fixtures

These fixtures calibrate the supplemental `AWS-LAMBDA-URL-*` evidence gates in `aws-review`. They are intentionally small so reviewers can distinguish an intended IAM-authenticated function URL from unauthenticated or under-documented exposure.

```yaml
case: iam_authenticated_cloudfront_function_url
surface:
  function: private_api
  function_url:
    authorization_type: AWS_IAM
    cors:
      allow_origins:
        - https://app.example.com
      allow_methods:
        - POST
      allow_headers:
        - authorization
        - content-type
        - x-amz-date
  intended_path:
    edge: cloudfront
    waf: enabled
    public_api_justification: internal_authenticated_application
resource_policy:
  action: lambda:InvokeFunctionUrl
  principal: cloudfront.amazonaws.com
  source_arn: arn:aws:cloudfront::123456789012:distribution/E123EXAMPLE
  function_url_auth_type: AWS_IAM
caller_identity_policy:
  allowed_principal: arn:aws:iam::123456789012:role/cloudfront-function-url-origin
  allowed_action: lambda:InvokeFunctionUrl
  resource_scoped_to_function: true
execution_role:
  admin_policy_attached: false
  secrets_scope: named_parameter_only
audit:
  cloudtrail_management_events: true
  lambda_url_change_alarm: true
  edge_logs: true
expected_decision: Pass
expected_findings: []
```

```yaml
case: unauthenticated_admin_url_with_admin_role
surface:
  function: admin_console
  function_url:
    authorization_type: NONE
    cors: missing
  intended_path:
    public_api_justification: missing
    edge: missing
    abuse_controls: missing
resource_policy:
  action: lambda:InvokeFunctionUrl
  principal: "*"
  function_url_auth_type: missing
caller_identity_policy: not_required_for_none_auth
execution_role:
  admin_policy_attached: true
  managed_policy_arn: arn:aws:iam::aws:policy/AdministratorAccess
audit:
  cloudtrail_management_events: true
  lambda_url_change_alarm: missing
  edge_logs: missing
expected_decision: Fail
expected_findings:
  - check: AWS-LAMBDA-URL-02
    severity: Critical
    reason: Unauthenticated sensitive Function URL lacks public justification, CORS, abuse-control, and edge-path evidence.
  - check: AWS-LAMBDA-URL-03
    severity: Critical
    reason: Resource policy allows broad public invocation without URL-specific constraints.
  - check: AWS-LAMBDA-URL-05
    severity: Critical
    reason: Public invocation is paired with AdministratorAccess execution-role blast radius.
```

```yaml
case: iam_auth_broad_caller_policy
surface:
  function: partner_callback
  function_url:
    authorization_type: AWS_IAM
    cors:
      allow_origins:
        - https://partners.example.com
  intended_path:
    public_api_justification: partner_signed_callback
resource_policy:
  action: lambda:InvokeFunctionUrl
  principal: arn:aws:iam::123456789012:role/partner-callback
  function_url_auth_type: AWS_IAM
caller_identity_policy:
  allowed_action: lambda:InvokeFunctionUrl
  resource: "*"
  role_trust_policy:
    external_id_condition: missing
    principal_account_scope: "*"
execution_role:
  admin_policy_attached: false
  secrets_scope: partner_callback_secret
audit:
  cloudtrail_management_events: true
  lambda_url_change_alarm: true
expected_decision: Fail
expected_findings:
  - check: AWS-LAMBDA-URL-04
    severity: High
    reason: AWS_IAM URL has a scoped resource policy but the caller role can be broadly assumed and invokes any Function URL resource.
```

```yaml
case: vpc_config_misread_as_private_url
surface:
  function: worker
  function_url:
    authorization_type: NONE
  vpc_config:
    subnet_type: private
    security_group: worker-egress-only
  review_claim: private subnet and security group make the Function URL private
resource_policy:
  action: lambda:InvokeFunctionUrl
  principal: "*"
execution_role:
  downstream_access:
    rds_cluster: customer_orders
    redis: session_cache
audit:
  cloudtrail_management_events: true
  lambda_url_change_alarm: missing
expected_decision: Fail
expected_findings:
  - check: AWS-LAMBDA-URL-06
    severity: High
    reason: VPC configuration controls dependency access, not inbound Function URL reachability.
  - check: AWS-LAMBDA-URL-05
    severity: High
    reason: Public invocation can reach VPC data stores through the function execution role and subnets.
```

```yaml
case: event_source_and_url_path_incomplete_audit
surface:
  function: image_processor
  function_url:
    authorization_type: AWS_IAM
  alternate_invocation_paths:
    - type: s3_bucket_notification
      source_account: 123456789012
      source_arn: missing
    - type: sqs_event_source_mapping
      queue_policy_reviewed: false
resource_policy:
  action: lambda:InvokeFunctionUrl
  principal: arn:aws:iam::123456789012:role/image-api
  function_url_auth_type: AWS_IAM
execution_role:
  s3_access: arn:aws:s3:::customer-images/*
audit:
  cloudtrail_management_events: true
  lambda_url_change_alarm: true
  add_permission_alarm: missing
  s3_trigger_change_alarm: missing
  queue_policy_change_alarm: missing
expected_decision: Fail
expected_findings:
  - check: AWS-LAMBDA-URL-07
    severity: Medium
    reason: Alternate S3 and SQS invocation paths are present but source constraints and queue policy evidence are incomplete.
  - check: AWS-LAMBDA-URL-08
    severity: Medium
    reason: Monitoring covers URL changes but misses permission and alternate trigger changes.
```

```yaml
case: function_url_missing_policy_exports
surface:
  function: reporting_api
  function_url:
    authorization_type: AWS_IAM
    cors:
      allow_origins:
        - https://reports.example.com
missing_artifacts:
  - lambda_resource_policy
  - caller_identity_policy
  - execution_role_policy
  - cloudtrail_metric_filters
available_artifacts:
  - aws_lambda_function_url Terraform resource
  - CloudFront distribution origin
expected_decision: Not Evaluable
expected_findings:
  - check: AWS-LAMBDA-URL-09
    severity: Medium
    reason: Function URL auth type is visible, but policy, caller, execution role, and audit artifacts are missing from the review evidence.
```
