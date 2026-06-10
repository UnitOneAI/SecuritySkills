"""Benign impersonation start: approval, reason, tenant, scope, and audit."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class StaffUser:
    id: str
    assigned_tenant: str
    mfa_recent: bool


@dataclass
class TargetUser:
    id: str
    tenant: str
    role: str


def start_impersonation(staff, target, approval):
    if not staff.mfa_recent:
        raise PermissionError("recent staff MFA required")
    if staff.assigned_tenant != target.tenant:
        raise PermissionError("staff is not assigned to target tenant")
    if approval["tenant"] != target.tenant or approval["target_user_id"] != target.id:
        raise PermissionError("approval does not match target")
    if not approval.get("reason") or not approval.get("ticket_id"):
        raise ValueError("reason and ticket are required")
    if target.role in {"tenant_owner", "billing_admin", "security_admin"}:
        raise PermissionError("high-risk target requires a separate workflow")

    return {
        "actor_id": staff.id,
        "target_user_id": target.id,
        "tenant_id": target.tenant,
        "scope": "read_only_support",
        "reason": approval["reason"],
        "ticket_id": approval["ticket_id"],
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=30),
        "is_impersonating": True,
    }


if __name__ == "__main__":
    session = start_impersonation(
        StaffUser("staff-1", "tenant-a", True),
        TargetUser("user-a", "tenant-a", "member"),
        {"tenant": "tenant-a", "target_user_id": "user-a", "reason": "support case", "ticket_id": "SUP-123"},
    )
    print(session)
