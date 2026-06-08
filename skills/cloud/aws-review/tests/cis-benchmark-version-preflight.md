# CIS Benchmark Version Preflight Test Cases

These fixtures exercise the version-aware reporting guardrails in `aws-review`.

## Current v5.0.0 Security Hub Evidence

### Input

Minimal ASFF-like Security Hub finding with CIS AWS v5.0.0 standard metadata:

```json
{
  "Findings": [
    {
      "AwsAccountId": "111122223333",
      "ProductFields": {
        "StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/5.0.0",
        "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:111122223333:subscription/cis-aws-foundations-benchmark/v/5.0.0"
      },
      "Compliance": {
        "Status": "FAILED",
        "SecurityControlId": "CloudTrail.1",
        "AssociatedStandards": [
          {
            "StandardsId": "standards/cis-aws-foundations-benchmark/v/5.0.0"
          }
        ]
      },
      "Resources": [{ "Id": "arn:aws:cloudtrail:us-east-1:111122223333:trail/org" }]
    }
  ]
}
```

### Expected Handling

- `benchmark_version`: `CIS AWS Foundations Benchmark v5.0.0`
- `security_hub_standard_arn_or_version`: `arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/5.0.0`
- `legacy_baseline`: `false`
- `control_support_status`: `current`
- Do not report `Total CIS recommendations evaluated: <N>/62` as the current v5.0.0 denominator.

## Legacy v3.0.0 IaC-Only Evidence

### Input

```hcl
resource "aws_securityhub_standards_subscription" "cis_v3" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/3.0.0"
}
```

### Expected Handling

- `benchmark_version`: `CIS AWS Foundations Benchmark v3.0.0`
- `security_hub_standard_arn_or_version`: `arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/3.0.0`
- `legacy_baseline`: `true`
- v3.0.0 section counts may be used only as legacy scoring.

## Missing Version Evidence

### Input

```text
Framework: CIS Amazon Web Services Foundations Benchmark
Total CIS recommendations evaluated: 62/62
```

### Expected Handling

- Request or infer the benchmark version before scoring.
- If no current mapping is present, mark the denominator source as `source-specific`.
- Keep current, legacy, removed, unsupported, manual, and not-evaluable counts separate.
