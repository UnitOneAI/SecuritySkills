# AI Rendering, API Auth, and Cloud Metadata SSRF Fixtures

These fixtures calibrate the supplemental `WEB-AI-*`, `WEB-AUTH-*`, and `WEB-SSRF-*` evidence gates in `owasp-top-10-web`.

```yaml
case: trusted_types_sanitized_model_summary
surface:
  source: llm_summary
  sink: dangerouslySetInnerHTML
  framework: react
  content_context: html_body
sanitization:
  trusted_types_enforced: true
  policy_name: app-ai-render
  sanitizer: DOMPurify
  allowed_tags:
    - p
    - ul
    - li
    - a
  url_schemes:
    - https
  csp:
    require_trusted_types_for: script
    trusted_types:
      - app-ai-render
tests:
  xss_payload_regression: passed
  sanitizer_config_reviewed: true
expected_decision: Pass
expected_findings: []
```

```yaml
case: raw_model_output_to_innerhtml
surface:
  source: chat_model_response
  sink: innerHTML
  framework: vanilla_js
  content_context: html_body
sanitization:
  trusted_types_enforced: false
  sanitizer: missing
  csp: missing
model_output_example: "<img src=x onerror=fetch('/api/export')>"
expected_decision: Fail
expected_findings:
  - category: A03:2021
    check: WEB-AI-02
    severity: High
    reason: Model output reaches an HTML sink without Trusted Types, sanitizer policy, or CSP evidence.
```

```yaml
case: markdown_renderer_allows_model_generated_javascript_links
surface:
  source: rag_document_excerpt
  sink: markdown_preview
  renderer_options:
    html: true
    linkify: true
    sanitize: false
generated_actions:
  links_can_autonavigate: true
  allowed_schemes:
    - http
    - https
    - javascript
    - data
expected_decision: Fail
expected_findings:
  - category: A03:2021
    check: WEB-AI-03
    severity: High
    reason: Generated Markdown can create active links and HTML with dangerous URL schemes.
  - category: A04:2021
    check: WEB-AI-04
    severity: Medium
    reason: Retrieved document instructions are not separated from rendered data provenance.
```

```yaml
case: passkey_and_dpop_api_flow_complete
surface:
  app_type: spa
  api: https://api.example.com
authentication:
  webauthn:
    rp_id: example.com
    origin: https://app.example.com
    challenge_freshness_seconds: 120
    user_verification: required
  oauth:
    flow: authorization_code
    public_client: true
    pkce: S256
    state: required
    nonce: required
    redirect_uri_allowlist: exact_match
    audience: https://api.example.com
token_replay_controls:
  dpop: true
  jti_replay_cache: true
  refresh_token_rotation: true
  reuse_detection: true
token_storage:
  access_token: memory_only
  refresh_token: httpOnly_sameSite_cookie
expected_decision: Pass
expected_findings: []
```

```yaml
case: public_client_bearer_tokens_replayable
surface:
  app_type: spa
  api: https://api.example.com
authentication:
  oauth:
    flow: implicit
    pkce: missing
    state: missing
    nonce: missing
    audience: missing
token_storage:
  access_token: localStorage
  refresh_token: localStorage
token_replay_controls:
  dpop: false
  mtls: false
  refresh_token_rotation: false
  reuse_detection: false
logging:
  url_fragments_logged_by_proxy: true
expected_decision: Fail
expected_findings:
  - category: A07:2021
    check: WEB-AUTH-01
    severity: High
    reason: Public client omits PKCE, state, nonce, and audience binding.
  - category: A07:2021
    check: WEB-AUTH-02
    severity: High
    reason: Browser-readable token storage and logged URL fragments expose bearer tokens.
  - category: A07:2021
    check: WEB-AUTH-03
    severity: High
    reason: Tokens are replayable from another client with no sender constraint or reuse detection.
```

```yaml
case: ssrf_filter_misses_metadata_redirects_and_encodings
surface:
  feature: link_preview
  input_parameter: url
http_client:
  follows_redirects: true
  redirect_destination_revalidated: false
  dns_rebinding_rechecked: false
normalization:
  parses_decimal_ipv4: false
  parses_octal_ipv4: false
  parses_ipv6_mapped_ipv4: false
  strips_userinfo: false
blocked_ranges:
  rfc1918: true
  link_local: false
  metadata_hostnames: false
cloud_metadata:
  aws_169_254_169_254: reachable
  gcp_metadata_google_internal: reachable
  attacker_can_set_metadata_flavor_header: true
  azure_imds: reachable
expected_decision: Fail
expected_findings:
  - category: A10:2021
    check: WEB-SSRF-01
    severity: Critical
    reason: URL validation does not re-check redirects, DNS rebinding, or alternate IP encodings.
  - category: A10:2021
    check: WEB-SSRF-02
    severity: Critical
    reason: Link-local and cloud metadata endpoints remain reachable despite generic private-range blocking.
```

```yaml
case: ssrf_runtime_controls_missing
surface:
  feature: import_from_url
  input_parameter: source_url
available_evidence:
  - application_allowlist_code
missing_artifacts:
  - deployment_cloud_provider
  - outbound_egress_policy
  - http_client_redirect_behavior
  - dns_resolution_recheck
  - metadata_service_hardening
  - workload_identity_scope
expected_decision: Not Evaluable
expected_findings:
  - category: A10:2021
    check: WEB-SSRF-04
    severity: Medium
    reason: Application allowlist exists, but runtime egress, redirect, DNS, metadata, and identity-scope evidence is missing.
```
