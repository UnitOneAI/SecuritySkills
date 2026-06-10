"""Vulnerable audit trail: impersonated actions are logged as the target user."""


AUDIT_LOG = []


def emit_audit(actor, action, resource):
    AUDIT_LOG.append({"actor": actor, "action": action, "resource": resource})


def handle_impersonated_request(session, action, resource):
    # Vulnerable: the staff actor is overwritten by the customer identity. A
    # destructive write now appears to have been performed by the customer.
    current_user_id = session["target_user_id"]
    emit_audit(current_user_id, action, resource)
    return {"ok": True}


if __name__ == "__main__":
    handle_impersonated_request(
        {"staff_user_id": "staff-7", "target_user_id": "customer-42"},
        "delete_api_token",
        "token-1",
    )
    print(AUDIT_LOG)
