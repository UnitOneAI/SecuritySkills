# AWS Access Analyzer External Access Calibration

Use these samples to calibrate `aws-review` external-access and archive lifecycle findings.

---

## Should Trigger: Broad Archive Rule Without Lifecycle Evidence

```yaml
access_analyzer:
  analyzer_scope:
    type: ORGANIZATION
    covered_regions: ["us-east-1", "us-west-2"]
  archive_rules:
    - name: archive-all-partner-findings
      filter:
        resource_type: AWS::S3::Bucket
        principal: "*"
      reason: "partner access is expected"
      owner: null
      ticket: null
      next_review_at: null
```

Expected finding:

- **Status:** Fail
- **Severity:** High
- **Reason:** The archive rule suppresses all S3 external findings with a wildcard principal and no owner, ticket, specific intended relationship, expiry, next review date, or revalidation trigger.

---

## Should Trigger: Active External Finding Without Intended-Access Evidence

```yaml
access_analyzer:
  analyzer_scope:
    type: ACCOUNT
    covered_regions: ["us-east-1"]
  findings:
    - id: finding-123
      state: ACTIVE
      resource_type: AWS::KMS::Key
      resource: arn:aws:kms:us-east-1:111122223333:key/abcd-1234
      principal:
        aws_account: "999988887777"
      source_policy_statement:
        Sid: AllowExternalDecrypt
        Effect: Allow
        Action: ["kms:Decrypt"]
        Principal:
          AWS: arn:aws:iam::999988887777:root
      owner: ""
      business_purpose: ""
      expires_at: null
      last_revalidated_at: null
```

Expected finding:

- **Status:** Fail
- **Severity:** High
- **Reason:** The active KMS external-access finding has no owner, intended principal justification, ticket, expiry, or last revalidation evidence.

---

## Should Not Trigger: Scoped Partner Finding With Current Review Evidence

```yaml
access_analyzer:
  analyzer_scope:
    type: ORGANIZATION
    zone_of_trust: o-exampleorg
    covered_accounts: ["111122223333", "444455556666"]
    covered_regions: ["us-east-1", "us-west-2", "eu-west-1"]
  findings:
    - id: finding-456
      state: ARCHIVED
      resource_type: AWS::SQS::Queue
      resource: arn:aws:sqs:us-east-1:111122223333:partner-settlement-events
      principal:
        service: events.amazonaws.com
      intended_external_account: "222233334444"
      source_policy_statement:
        Sid: AllowPartnerSettlementEvents
        Effect: Allow
        Action: ["sqs:SendMessage"]
        Principal:
          Service: events.amazonaws.com
        Condition:
          StringEquals:
            aws:SourceAccount: "222233334444"
          ArnLike:
            aws:SourceArn: arn:aws:events:us-east-1:222233334444:rule/settlement-*
      archive_reason: "approved partner settlement integration"
      owner: platform-security
      ticket: SEC-2026-0188
      business_purpose: "partner settlement event ingestion"
      last_revalidated_at: "<last-review RFC3339>"
      expires_at: "<contract-renewal - 30d RFC3339>"
      next_review_at: "<last-review + 90d RFC3339>"
      revalidate_on:
        - policy_change
        - principal_change
        - organization_change
```

Expected handling:

- **Status:** Pass
- **Reason:** The archived external-access finding is scoped to a specific partner role and queue, constrained by source account/ARN, and has owner, ticket, business purpose, expiry, next review date, and revalidation triggers.
