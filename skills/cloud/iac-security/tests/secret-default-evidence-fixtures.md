# IaC Secret Default Evidence Fixtures

Use these fixtures to calibrate hardcoded-secret review of Terraform `sensitive`
variables and CloudFormation `NoEcho` parameters.

## Vulnerable: Terraform Sensitive Variable With Plaintext Default

```hcl
variable "db_password" {
  type      = string
  sensitive = true
  default   = "SuperSecret123!"
}
```

Expected result: fail. `sensitive = true` suppresses display in some Terraform
surfaces, but the default still commits a plaintext credential-like value.

## Benign: Terraform Sensitive Variable Without Default

```hcl
variable "db_password" {
  type      = string
  sensitive = true
}
```

Expected result: pass. The value is not stored in source and can be supplied at
runtime, by CI, or through a secret-management workflow.

## Vulnerable: CloudFormation NoEcho Parameter With Plaintext Default

```yaml
Parameters:
  DBPassword:
    Type: String
    NoEcho: true
    Default: SuperSecret123!
```

Expected result: fail. `NoEcho` masks some display paths but does not protect a
source-controlled default value in the template.

## Benign: CloudFormation NoEcho Parameter Without Default

```yaml
Parameters:
  DBPassword:
    Type: String
    NoEcho: true
```

Expected result: pass. The template declares a sensitive parameter without
embedding the value.

## Review Boundary

Do not treat empty strings, `example`, `changeme`, `REPLACE_ME`, or other obvious
placeholders as confirmed credentials unless adjacent deployment context proves
that the placeholder is actually used as a live secret.
