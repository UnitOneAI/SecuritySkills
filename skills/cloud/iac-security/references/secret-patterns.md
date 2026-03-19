# IaC Secret Detection Patterns Reference

Extracted from [tool-rules.md](../tool-rules.md). This file consolidates all regex patterns used for detecting hardcoded secrets in Infrastructure as Code files.

---

## AWS Credential Patterns

```
AKIA[0-9A-Z]{16}
aws_secret_access_key
aws_access_key_id
```

## Azure Credential Patterns

```
client_secret
tenant_id.*secret
password\s*=
```

## GCP Credential Patterns

```
private_key_id
private_key.*BEGIN
```

## Generic Secret Patterns

```
api_key\s*=
api_secret
secret_key\s*=
token\s*=\s*"[^"]{8,}"
password\s*=\s*"[^"]{1,}"
private_key\s*=
```

## Database Credential Patterns

```
db_password
database_password
master_password
admin_password
```

## Connection String Patterns

```
mongodb\+srv://[^:]+:[^@]+@
postgres://[^:]+:[^@]+@
mysql://[^:]+:[^@]+@
amqp://[^:]+:[^@]+@
redis://:[^@]+@
```

## Additional High-Confidence Patterns

```
# SSH private keys
-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----

# GitHub tokens
gh[pousr]_[A-Za-z0-9_]{36,}

# Generic API tokens with hex/base64 values
api[_-]?token\s*[:=]\s*["'][A-Za-z0-9+/=_-]{20,}["']

# JWT tokens
eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*

# Slack tokens
xox[bpors]-[0-9A-Za-z-]+

# Stripe keys
sk_live_[0-9a-zA-Z]{24,}
rk_live_[0-9a-zA-Z]{24,}

# SendGrid API key
SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}

# Twilio
SK[0-9a-fA-F]{32}
```

---

## Usage Notes

- **Severity:** Critical for any confirmed hardcoded secret.
- **False positive filter:** A value assigned via `var.`, `data.`, `local.`, or `module.` reference is NOT a hardcoded secret. Only flag literal string values.
- **Checkov equivalents:** CKV_SECRET_1 through CKV_SECRET_80
- **tfsec equivalents:** general-secrets-sensitive-in-variable, general-secrets-sensitive-in-attribute
