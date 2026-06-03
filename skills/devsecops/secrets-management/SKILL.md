# Secrets Management Review Skill

## Overview

This skill helps security reviewers evaluate how an application or CI/CD pipeline manages secrets (API keys, passwords, certificates, database credentials, cloud access keys, etc.). The goal is to ensure secrets are stored securely, rotated regularly, and never exposed in code, logs, or artifacts.

## Key Review Areas

### 1. Static Secrets in Code or Configuration

- **Check for hardcoded secrets** in source code, configuration files, environment files, Dockerfiles, CI/CD YAML, and infrastructure-as-code templates.
- **Check for secrets in version control history** — even if removed later, secrets in Git history are compromised.
- **Verify use of secret scanning tools** (e.g., GitHub secret scanning, truffleHog, Gitleaks) in CI/CD pipelines.

### 2. Secret Storage and Access

- **Prefer a dedicated secrets manager** (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GitHub Actions Secrets, Doppler).
- **Ensure secrets are encrypted at rest and in transit.**
- **Verify access controls** — who can read, write, rotate secrets? Use least-privilege IAM policies.
- **Check for audit logging** of secret access and modifications.

### 3. CI/CD Pipeline Secrets

- **Avoid injecting secrets as plaintext environment variables** in CI/CD logs or build output.
- **Use masked variables** in CI/CD platforms (GitHub Actions, GitLab CI, Jenkins).
- **Prefer OIDC-based authentication** over static cloud credentials in CI/CD workflows.

#### OIDC Trust Policy Review

When a CI/CD workflow uses OIDC to authenticate to a cloud provider, the security of the exchange depends on the cloud-side trust policy. Reviewers must verify:

- **`sub` (subject) condition**: The trust policy should restrict which GitHub repository, branch, or environment can assume the role. A missing `sub` condition allows any workflow in any repository to assume the role.
- **`aud` (audience) condition**: The trust policy should specify the expected audience (e.g., `sts.amazonaws.com` for AWS). A missing or overly permissive `aud` condition weakens security.

**Example of a restrictive AWS trust policy (recommended):**

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
    }
  }
}
```

**Example of a permissive AWS trust policy (should be flagged):**

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
  }
}
```

> **Why the permissive policy is risky:** Without a `sub` condition, any GitHub Actions workflow in any repository can request a token for this role, potentially allowing unauthorized access to cloud resources.

### 4. Secret Rotation

- **Verify rotation policies** are defined and enforced (e.g., every 90 days for database passwords, every 30 days for high-risk keys).
- **Check for automated rotation** mechanisms (e.g., AWS Secrets Manager automatic rotation, custom scripts).
- **Ensure rotation does not cause downtime** — use blue/green deployment or versioned secrets.

### 5. Incident Response for Secret Leaks

- **Confirm there is a process** for revoking and rotating leaked secrets immediately.
- **Check for monitoring** of secret access anomalies (e.g., unusual geographic access, high-frequency access).
- **Verify that leaked secrets are not reused** across environments.

## False Positive Awareness

- **OIDC workflow YAML with `id-token: write` permission is not itself a secret leak.** The permission allows the workflow to request an OIDC JWT, which is then exchanged for cloud credentials. The security decision depends on the cloud-side trust policy.
- **Do not flag the presence of `id-token: write` alone** as a credential exposure. Instead, request evidence of the corresponding cloud trust policy and review its `sub` and `aud` conditions.

## Review Checklist

- [ ] No hardcoded secrets in code, config, or history
- [ ] Secrets stored in a dedicated secrets manager
- [ ] Secrets encrypted at rest and in transit
- [ ] Access to secrets follows least-privilege principle
- [ ] Audit logging enabled for secret access
- [ ] CI/CD secrets are masked in logs
- [ ] OIDC trust policies include restrictive `sub` and `aud` conditions
- [ ] Rotation policies defined and automated where possible
- [ ] Incident response plan for secret leaks exists

## References

- [GitHub: About security hardening with OpenID Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [AWS: Using OIDC with GitHub Actions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [OWASP: Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)