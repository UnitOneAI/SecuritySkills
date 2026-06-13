# Vulnerable: password change only checks ordinary login

```python
@router.post("/account/password")
def change_password(request, body):
    user = require_login(request)
    update_password(user.id, body.new_password)
    revoke_password_reset_tokens(user.id)
    return {"ok": True}
```

Expected finding: `STEPUP-INV-02` and `STEPUP-ENF-02`. A stale authenticated session can change the password without a recent authentication or MFA event.

