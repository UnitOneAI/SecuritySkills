# AWS Organizations Evidence Edge Cases

These fixtures validate that `aws-review` does not treat a single-account CIS
export as proof of organization-wide coverage.

## Edge Case 1: SCP Exists But Is Not Attached

Input evidence:

```yaml
organization:
  production_ou: ou-prod
scp:
  name: deny-public-s3
  attached_to:
    - ou-dev
  expected_attachment:
    - ou-prod
```

Expected output:

- Finding ID: `AWS-ORG-02`
- Severity: High because the stated guardrail does not apply to production
- Remediation requires attaching or replacing the guardrail and testing exception accounts

## Edge Case 2: Organization Trail Missing Opt-In Regions

Input evidence:

```yaml
cloudtrail:
  type: organization_trail
  is_multi_region_trail: true
  include_management_events: true
  opt_in_regions_enabled:
    - ap-east-1
  log_file_validation_enabled: true
coverage_test:
  ap-east-1_management_event_seen: false
```

Expected output:

- Finding ID: `AWS-ORG-03`
- Severity: High for production organizations
- Require evidence that opt-in regions and management events are delivered to the log archive

## Edge Case 3: Break-Glass Account Excluded From Guardrails

Input evidence:

```yaml
account:
  id: "111122223333"
  purpose: break_glass
  ou: security-exceptions
  scp_exempt: true
exception_register:
  owner: null
  expiry: null
  monitoring: missing
```

Expected output:

- Finding ID: `AWS-ORG-07`
- Severity: High
- Require owner, expiry, monitoring, compensating controls, and review cadence
