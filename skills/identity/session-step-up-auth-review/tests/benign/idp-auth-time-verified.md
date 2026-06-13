# Benign: IdP auth_time is verified by backend

```python
claims = verify_id_token(
    token,
    issuer="https://idp.example.com",
    audience="admin-console",
    nonce=session.step_up_nonce,
)

if claims["auth_time"] < now() - timedelta(minutes=5):
    raise Forbidden("reauthentication required")
if "mfa" not in claims["amr"]:
    raise Forbidden("MFA required")
```

Expected result: do not flag as client-controlled step-up. The backend verifies issuer, audience, nonce, `auth_time`, and `amr`.

