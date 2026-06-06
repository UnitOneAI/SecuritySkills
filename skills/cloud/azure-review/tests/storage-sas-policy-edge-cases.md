# Azure Storage SAS and Effective Access Edge Cases

These fixtures cover storage accounts that pass common CIS-style storage controls but remain exposed through SAS bearer tokens, Shared Key authorization, external principals, or ADLS Gen2 ACL divergence.

## Case 1: Private Storage With Long-Lived Account SAS

Input evidence:

```hcl
resource "azurerm_storage_account" "records" {
  name                            = "prodrecords"
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true
}
```

Operational export:

```text
sv=2025-01-01&ss=bf&srt=sco&sp=rwdlacupiytfx&se=2028-12-31T23:59:59Z
```

Expected review:

- CIS public-access/TLS checks may pass.
- Storage Bearer Access Review fails because Shared Key is enabled and an account SAS is broad and long-lived.
- Severity is High when the account stores sensitive or externally shared data.
- Remediation requires migration to Microsoft Entra ID/user delegation SAS where possible, maximum expiry policy, and key rotation or revocation plan.

## Case 2: Service SAS Without Stored Access Policy

Input evidence:

```yaml
storage_account: auditlogs
container: exports
service_sas:
  permissions: rwdl
  expiry: 180d
  stored_access_policy: null
diagnostic_logs:
  authentication_types:
    - SAS
```

Expected review:

- Finding is High if the SAS grants write/delete/list to sensitive exports and no stored access policy or alternative revocation evidence exists.
- Finding is Medium if logs show SAS usage but do not identify caller, token class, or expiry.
- The report records `Stored Access Policy` as `Missing` and `Status` as `Fail`.

## Case 3: User Delegation SAS With Bounded Scope

Input evidence:

```yaml
storage_account: datalakecurated
allow_shared_key_access: false
user_delegation_sas:
  service: blob
  permissions: rl
  expiry: 4h
  requester: managed_identity_exporter
diagnostic_logs:
  authentication_types:
    - OAuth
    - SAS
```

Expected review:

- User delegation SAS is preferred for Blob/Data Lake when bounded and backed by Microsoft Entra ID.
- The review still records expiry, scope, and caller evidence.
- No High finding is created solely because SAS exists.

## Case 4: External Guest Group and ADLS ACL Divergence

Input evidence:

```yaml
rbac:
  - principal: external-audit-guests
    principal_type: group
    role: Storage Blob Data Contributor
    scope: /subscriptions/000/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/lake
access_review:
  last_completed: null
adls_acl:
  path: /finance/raw
  access_acl:
    - group:external-audit-guests:rwx
  default_acl:
    - group:external-audit-guests:rwx
```

Expected review:

- Finding is High for stale external contributor access without access-review evidence.
- The report records external principals as `Unreviewed`.
- The ADLS ACL/RBAC parity column is `Divergent` if the approved model does not allow external write access to `/finance/raw`.
