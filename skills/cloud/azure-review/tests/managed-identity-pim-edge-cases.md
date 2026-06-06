# Managed Identity and PIM Edge Cases

These fixtures verify that `azure-review` evaluates effective identity access, managed-identity attachability, PIM controls, inherited scope, and Key Vault authorization mode before scoring Azure identity findings.

```yaml
case_id: AZ-ID-01
title: Reader managed identity at subscription scope is benign
principal:
  type: user_assigned_managed_identity
  role: Reader
  scope: subscription
  data_actions: []
  owner: app-platform
attachability:
  allowed_compute:
    - app-prod-vmss
  change_control: MI-2026-044
expected_classification:
  status: Benign / least privilege
  reason: "Reader has no privileged dataActions and the attachable compute/purpose are documented."
```

```yaml
case_id: AZ-ID-02
title: Managed identity has Key Vault Administrator without attachability controls
principal:
  type: user_assigned_managed_identity
  role: Key Vault Administrator
  scope: /subscriptions/0000/resourceGroups/prod/providers/Microsoft.KeyVault/vaults/payments
  data_actions:
    - Microsoft.KeyVault/vaults/secrets/*
attachability:
  allowed_compute: unknown
  assignment_guardrail: missing
justification: missing
expected_classification:
  status: High-impact managed identity
  severity: High
  reason: "A workload identity can administer Key Vault secrets without scope justification or attachability controls."
```

```yaml
case_id: AZ-ID-03
title: PIM eligibility lacks activation evidence
principal:
  type: user
  role: Privileged Role Administrator
  scope: tenant
pim:
  state: eligible
  activation_duration: missing
  mfa_on_activation: missing
  approval_required: missing
  justification_required: missing
  audit_logs: missing
expected_classification:
  status: PIM evidence gap
  reason: "Eligibility cannot be treated as governed privileged access without activation policy and audit evidence."
```

```yaml
case_id: AZ-ID-04
title: PIM activation is controlled and auditable
principal:
  type: group
  role: User Access Administrator
  scope: subscription
pim:
  state: eligible
  activation_duration: PT2H
  authentication_strength: phishing-resistant MFA
  approval_required: true
  justification_required: true
  alerting_enabled: true
  audit_log_sample: present
expected_classification:
  status: Benign / controlled
  reason: "Privileged activation has duration, strong MFA, approval, justification, alerting, and logs."
```

```yaml
case_id: AZ-ID-05
title: Management-group inherited role is missing from subscription IaC
principal:
  type: group
  role: Owner
  direct_subscription_assignment: missing
effective_assignment_export:
  management_group_inherited: present
  member_accounts_reviewed: missing
expected_classification:
  status: Inherited-scope blind spot
  severity: Not Evaluable
  reason: "Subscription-local IaC is insufficient when Owner is inherited from a management group."
```

```yaml
case_id: AZ-ID-06
title: Key Vault access-policy mode makes RBAC-only remediation incomplete
key_vault:
  name: legacy-vault
  enable_rbac_authorization: false
access_policy:
  principal: app-sp
  permissions:
    secrets:
      - get
      - list
      - set
rbac_role_assignments: none
expected_classification:
  status: Key Vault mode mismatch
  severity: Medium
  reason: "The vault uses access policies, so RBAC-only review/remediation will miss effective secret permissions."
```

```yaml
case_id: AZ-ID-07
title: Federated workload credential can use privileged app path
principal:
  type: service_principal
  role: Contributor
  scope: resource_group
federated_credentials:
  issuer: https://token.actions.githubusercontent.com
  subject: repo:example/payments:ref:refs/heads/main
controls:
  branch_protection_evidence: missing
  environment_approval: missing
  credential_owner: missing
expected_classification:
  status: High-impact managed identity
  severity: High
  reason: "Federated workload identity can exercise privileged access without source control and approval evidence."
```
