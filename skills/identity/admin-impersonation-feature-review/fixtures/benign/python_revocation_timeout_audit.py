"""Benign session lifecycle: timeout, revocation, and dual-identity audit."""

from datetime import datetime, timedelta, timezone


AUDIT_LOG = []


def emit_audit(session, action, resource, outcome):
    AUDIT_LOG.append(
        {
            "actor_id": session["actor_id"],
            "target_user_id": session["target_user_id"],
            "tenant_id": session["tenant_id"],
            "session_id": session["session_id"],
            "ticket_id": session["ticket_id"],
            "action": action,
            "resource": resource,
            "outcome": outcome,
        }
    )


def ensure_active(session, revoked_approvals):
    now = datetime.now(timezone.utc)
    if now >= session["expires_at"]:
        raise PermissionError("session expired")
    if session["approval_id"] in revoked_approvals:
        raise PermissionError("approval revoked")


def handle_request(session, action, resource, revoked_approvals):
    ensure_active(session, revoked_approvals)
    emit_audit(session, action, resource, "allowed")
    return {"ok": True}


if __name__ == "__main__":
    support_session = {
        "actor_id": "staff-1",
        "target_user_id": "user-a",
        "tenant_id": "tenant-a",
        "session_id": "imp-123",
        "ticket_id": "SUP-123",
        "approval_id": "approval-1",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    handle_request(support_session, "view_invoice", "invoice-1", set())
    print(AUDIT_LOG)
