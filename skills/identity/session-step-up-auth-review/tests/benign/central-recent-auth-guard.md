# Benign: centralized recent-auth guard

```python
@router.post("/account/password")
def change_password(request, body):
    user = require_login(request)
    require_recent_auth(
        actor_id=user.id,
        session_id=request.session.id,
        action_class="security_setting",
        max_age_minutes=10,
        required_assurance="mfa",
    )
    update_password(user.id, body.new_password)
    revoke_other_sessions(user.id)
    return {"ok": True}
```

Expected result: do not flag missing step-up. The backend enforces recent authentication with action class, session binding, assurance, and revocation.

