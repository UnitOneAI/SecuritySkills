# AI, API, and Metadata Evidence Fixtures

These fixtures calibrate the supplemental evidence gates in `owasp-top-10-web`.
They are not executable tests. Use them as review scenarios when deciding whether a
finding should be reported, downgraded, or marked Not Evaluable.

## Fixture Format

Each fixture records:

- `source`: the untrusted input or system boundary.
- `sink`: the code path or infrastructure boundary being reviewed.
- `evidence`: proof required before calling the path safe.
- `expected_decision`: the expected review outcome.
- `evidence_gate`: the output value to use in a finding or benign note.

## Fixtures

```yaml
id: web-ai-safe-text-render
source: LLM answer assembled from user prompt and retrieved snippets.
sink: React message component renders the answer as text nodes.
evidence:
  - No dangerouslySetInnerHTML, v-html, raw template, or Markdown HTML mode is used.
  - URLs are rendered only after scheme and host allowlist checks.
  - CSP blocks inline script and reports violations.
expected_decision: benign_with_evidence
evidence_gate: AI render gate
notes: Do not report XSS solely because the model output contains script-like text.
```

```yaml
id: web-ai-rich-markdown-xss
source: Retrieved documentation and tool output are passed into a Markdown preview.
sink: Markdown renderer allows raw HTML and writes output to innerHTML.
evidence:
  - No Trusted Types policy is enforced for the HTML sink.
  - Sanitizer configuration is absent or cannot be inspected.
  - Links are not checked for javascript, data, or open-redirect navigation.
expected_decision: finding_expected
evidence_gate: AI render gate
owasp_category: A03:2021 - Injection
minimum_severity: High
```

```yaml
id: web-ai-safe-rich-html
source: Assistant response containing Markdown, links, and inline code examples.
sink: Rich-text component accepts only sanitized TrustedHTML.
evidence:
  - Sanitizer allowlist strips script, event handlers, dangerous URL schemes, and form controls.
  - Trusted Types or equivalent framework binding protects the HTML sink.
  - CSP forbids unsafe inline script and records violation reports.
expected_decision: benign_with_evidence
evidence_gate: AI render gate
notes: Keep as Not Evaluable when the sanitizer policy or CSP cannot be inspected.
```

```yaml
id: api-auth-high-risk-passkey-dpop
source: Public SPA calls administrative API endpoints.
sink: OAuth/OIDC public-client flow and API token validation.
evidence:
  - WebAuthn or passkey challenge is verified for privileged sessions.
  - PKCE S256, state, nonce, issuer, audience, and exact redirect URI are validated.
  - DPoP or mTLS sender-constrains access tokens for high-risk actions.
  - Refresh-token rotation and replay detection are logged.
expected_decision: benign_with_evidence
evidence_gate: API auth gate
```

```yaml
id: api-auth-replayable-browser-token
source: Browser public client stores bearer and refresh tokens in localStorage.
sink: API accepts bearer tokens for payments, admin actions, or sensitive data export.
evidence:
  - PKCE, nonce, and audience checks are missing or cannot be verified.
  - Tokens are not sender-constrained with DPoP, mTLS, or an equivalent proof.
  - Refresh-token rotation, revocation, and replay alerts are absent.
expected_decision: finding_expected
evidence_gate: API auth gate
owasp_category: A07:2021 - Identification and Authentication Failures
minimum_severity: High
```

```yaml
id: metadata-ssrf-defended-fetcher
source: User-submitted webhook URL fetched by a server-side worker.
sink: HTTP client in a cloud-hosted workload.
evidence:
  - URL allowlist or business-domain policy is enforced before fetch.
  - Redirects, DNS rebinding, IPv6, decimal, octal, and encoded link-local variants are blocked.
  - Egress policy denies cloud metadata endpoints unless explicitly required.
  - AWS IMDSv2 hop-limit, GCP Metadata-Flavor expectations, or Azure IMDS restrictions are documented when applicable.
expected_decision: benign_with_evidence
evidence_gate: cloud metadata SSRF gate
```

```yaml
id: metadata-ssrf-filter-bypass
source: User-controlled callback URL.
sink: Server follows redirects and fetches resolved hosts from cloud runtime.
evidence:
  - Filter blocks only the literal string 169.254.169.254.
  - Redirect targets are not revalidated after following 30x responses.
  - DNS rebinding and IPv6 link-local forms are not rejected.
  - No network egress policy blocks AWS, GCP, Azure, or Kubernetes metadata services.
expected_decision: finding_expected
evidence_gate: cloud metadata SSRF gate
owasp_category: A10:2021 - Server-Side Request Forgery
minimum_severity: High
```
