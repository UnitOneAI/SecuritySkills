# iam-review Test Fixtures

These fixtures document the intended behavior for the NIST SP 800-63B-4
authenticator evidence refresh.

- `benign/mfa-password-12char-passkey.yaml` covers a privileged account where a
  12-character password is used only as one factor in an MFA flow. It should not
  produce the single-factor password length finding.
- `vulnerable/syncable-passkey-aal3-downgrade.yaml` covers a policy that claims
  AAL3 while allowing syncable passkeys and weak recovery paths. It should
  produce `IAM-AUTH-06`, `IAM-AUTH-11`, and `IAM-AUTH-12`.

The fixtures are intentionally small and parser-agnostic so reviewers can use
them as regression inputs for any future skill runner or static validation
harness.
