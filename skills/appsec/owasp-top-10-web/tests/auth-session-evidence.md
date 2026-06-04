# Authentication and Session Evidence Fixtures

These fixtures calibrate `owasp-top-10-web` A07 checks against NIST SP 800-63B-4 and OWASP ASVS 5.0 password/session evidence.

## Vulnerable Fixture 1: Single-Factor Password Uses Legacy Baseline

```ts
const passwordPolicy = {
  minLength: 12,
  mfaRequired: false,
  breachedPasswordCheck: true,
  requireUppercase: false,
  requireDigit: false,
  requireSymbol: false,
  allowPaste: true
};
```

Expected result:

- Report A07 as `Fail` because this is a single-factor password context with a stale minimum length.
- Record the assurance context instead of treating `minLength: 12` as acceptable by itself.
- Do not add a composition-rule finding because the absence of composition rules is not the problem.

## Vulnerable Fixture 2: Composition Rules Reject Strong Passphrases

```ts
const passwordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireDigit: true,
  requireSymbol: true,
  disallowSpaces: true,
  disallowUnicode: true,
  blockPasswordManagers: true
};

passwordInput.addEventListener("paste", event => event.preventDefault());
```

Expected result:

- Report legacy composition and usability-hostile password policy evidence.
- Flag space/Unicode rejection and paste/password-manager blocking.
- Recommend length, blocklist, rate limiting, and MFA evidence instead of arbitrary composition rules.

## Vulnerable Fixture 3: Password Transformed Before Verification

```python
def verify_password(submitted: str, stored_hash: str) -> bool:
    normalized = submitted.strip().lower()[:32]
    return argon2.verify(stored_hash, normalized)
```

Expected result:

- Report exact-verification failure because the submitted password is stripped, lowercased, and truncated before verification.
- Record maximum-length and transformation evidence.
- Do not recommend normalization that would surprise users or weaken the verifier.

## Vulnerable Fixture 4: Session Evidence Too Generic

```yaml
session:
  token_entropy_bits: unknown
  backend_verification: unknown
  rotates_on_login: true
  rotates_on_reauth: unknown
  inactivity_timeout: undocumented
  absolute_lifetime: undocumented
  concurrent_session_policy: undocumented
  sso_session_coordination: unknown
```

Expected result:

- Report `Not Evaluable` or `Fail` for missing ASVS 5.0 session evidence.
- Require backend token verification, reference-token entropy, rotation on authentication and re-authentication, idle/absolute lifetime, concurrent-session policy, and SSO coordination.

## Benign Fixture 1: Modern Password Policy Without Composition Rules

```ts
const passwordPolicy = {
  minLength: 15,
  maxLength: 128,
  mfaRequired: false,
  requireUppercase: false,
  requireLowercase: false,
  requireDigit: false,
  requireSymbol: false,
  allowPaste: true,
  allowSpaces: true,
  allowUnicode: true,
  blocklist: ["password", "qwerty123456789", "companyname2026"],
  breachedPasswordCheck: true
};
```

Expected result:

- Do not report absence of composition rules as weak.
- Mark password evidence as acceptable when length, blocklist, paste/password-manager support, and exact verification are documented.

## Benign Fixture 2: MFA Context Explains Shorter Password Minimum

```yaml
password:
  min_length: 8
  use_context: "one factor in phishing-resistant MFA"
  blocklist: "HIBP k-anonymity plus tenant-specific terms"
  composition_rules: "none"
  paste_password_manager_support: true
mfa:
  required: true
  method: "FIDO2/WebAuthn platform authenticator"
```

Expected result:

- Do not apply the single-factor password minimum without considering MFA context.
- Record the assurance context and MFA evidence in the A07 table.

## Benign Fixture 3: ASVS 5.0 Session Evidence Present

```yaml
session:
  backend_verification: "server-side session lookup"
  reference_token_entropy_bits: 192
  generated_by: "CSPRNG"
  rotates_on_login: true
  rotates_on_reauth: true
  inactivity_timeout: "30 minutes, risk accepted"
  absolute_lifetime: "12 hours"
  concurrent_session_policy: "maximum 3 active sessions; oldest session terminated"
  sso_session_coordination: "local logout calls IdP logout and clears relying-party session"
```

Expected result:

- Mark session evidence as `Pass` for backend verification, entropy, rotation, idle/absolute lifetime, concurrent-session policy, and SSO coordination.
- Do not create a broad A07 session finding when all table fields are documented and implemented.
