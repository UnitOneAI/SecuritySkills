"""Benign approval token binding for exact tool, action, tenant, and resource."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class ApprovalToken:
    actor_id: str
    tenant_id: str
    resource_id: str
    tool_name: str
    action: str
    policy_version: str
    expires_at: datetime


def mint_approval(actor_id, tenant_id, resource_id, tool_name, action, policy_version):
    return ApprovalToken(
        actor_id=actor_id,
        tenant_id=tenant_id,
        resource_id=resource_id,
        tool_name=tool_name,
        action=action,
        policy_version=policy_version,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )


def can_execute(token, actor_id, tenant_id, resource_id, tool_name, action, policy_version):
    expected = (
        token.actor_id == actor_id
        and token.tenant_id == tenant_id
        and token.resource_id == resource_id
        and token.tool_name == tool_name
        and token.action == action
        and token.policy_version == policy_version
    )
    return expected and datetime.now(timezone.utc) < token.expires_at


if __name__ == "__main__":
    approval = mint_approval("agent-1", "tenant-a", "invoice-7", "invoice.send", "write", "v3")
    print(can_execute(approval, "agent-1", "tenant-a", "invoice-7", "invoice.send", "write", "v3"))
