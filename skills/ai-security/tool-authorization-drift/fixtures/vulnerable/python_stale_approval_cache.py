"""Vulnerable approval cache: approval is not bound to action or resource."""

from datetime import datetime, timedelta, timezone


APPROVAL_CACHE = {}


def cache_key(actor_id, tenant_id):
    # Vulnerable: missing tool name, action, resource, policy version, and scope.
    return f"{actor_id}:{tenant_id}"


def approve(actor_id, tenant_id):
    APPROVAL_CACHE[cache_key(actor_id, tenant_id)] = {
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=4),
    }


def can_execute(actor_id, tenant_id, tool_name, resource_id):
    approval = APPROVAL_CACHE.get(cache_key(actor_id, tenant_id))
    if not approval:
        return False
    return datetime.now(timezone.utc) < approval["expires_at"]


if __name__ == "__main__":
    approve("agent-1", "tenant-a")
    print(can_execute("agent-1", "tenant-a", "payment.execute", "payment-9"))
