# CSRF Credential Transport Fixtures

Use these fixtures when reviewing CSRF and SameSite findings in `owasp-top-10-web`. The goal is to avoid noisy "missing CSRF token" findings on endpoints that do not accept browser-managed credentials while still catching cookie-authenticated high-value actions.

## Benign: Explicit Bearer Token API

```javascript
app.post("/api/profile", requireBearerToken, express.json(), async (req, res) => {
  await updateProfile(req.user.id, req.body);
  res.sendStatus(204);
});

function requireBearerToken(req, res, next) {
  const header = req.get("Authorization");
  if (!header?.startsWith("Bearer ")) return res.sendStatus(401);
  req.user = verifyAccessToken(header.slice("Bearer ".length));
  next();
}
```

Expected review outcome:

- Do not report missing CSRF token by default.
- Record `ambient_credentials_accepted: no`.
- Confirm the route does not also accept session cookies, refresh cookies, or fallback Basic/Digest credentials.

## Vulnerable: Cookie-Authenticated High-Value Action

```javascript
app.post("/account/email", requireSessionCookie, express.urlencoded({ extended: false }), async (req, res) => {
  await changeEmail(req.session.userId, req.body.email);
  res.redirect("/account");
});
```

Expected review outcome:

- Report CSRF if no synchronizer token, double-submit token, strict Origin/Referer validation, or equivalent framework protection is enforced.
- Record `ambient_credentials_accepted: yes`.
- Treat `SameSite=Lax` as helpful defense-in-depth, not a complete replacement for CSRF validation on this high-value mutation.

## Contextual: OIDC Callback or Embedded Cross-Site Flow

```http
Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=None
```

```yaml
documented_cross_site_use:
  - oidc_login_callback
  - saml_assertion_consumer_service
  - embedded_partner_app
required_controls:
  - secure_cookie: true
  - csrf_token_or_oidc_state: present
  - origin_or_referer_check: present_for_state_changing_routes
  - callback_destination_allowlist: present
```

Expected review outcome:

- Do not flag `SameSite=None` by itself when `Secure` is present and the cross-site flow is documented.
- Flag missing CSRF/OIDC `state` or missing Origin/Referer validation when the route changes account state.
- Record `ambient_credentials_accepted: yes` because cookies are browser-managed.

## Hybrid: Bearer Access Token plus Refresh Cookie

```yaml
access_api:
  auth: Authorization Bearer access token
  accepts_cookies: false
refresh_endpoint:
  auth: HttpOnly refresh cookie
  method: POST
  csrf_token: missing
```

Expected review outcome:

- Do not report CSRF on the bearer-only access API.
- Review the refresh endpoint separately and report CSRF if the cookie-authenticated refresh action lacks token/state or strict Origin/Referer validation.
