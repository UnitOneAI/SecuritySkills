def enqueue_export(user, request, authz, queue):
    scope = authz.snapshot(
        actor_id=user.id,
        tenant_id=user.tenant_id,
        action="orders.export",
        object_filter={"order_ids": request["order_ids"]},
        fields=["id", "status", "total"],
        ttl_seconds=900,
    )
    queue.push("orders-export", {"job_id": request["job_id"], "scope_id": scope.id})


def run_export_job(job, authz, db, object_store):
    scope = authz.load_snapshot(job["scope_id"])
    authz.require_snapshot_valid(scope)

    allowed_order_ids = [
        order_id
        for order_id in scope.object_filter["order_ids"]
        if authz.can(scope.actor_id, "orders.export", tenant_id=scope.tenant_id, object_id=order_id)
    ]

    rows = db.orders.find_many(
        tenant_id=scope.tenant_id,
        ids=allowed_order_ids,
        fields=scope.fields,
    )
    object_store.put_private(
        key=f"exports/{scope.tenant_id}/{job['job_id']}.csv",
        body=render_csv(rows),
        metadata={
            "actor_id": scope.actor_id,
            "tenant_id": scope.tenant_id,
            "scope_id": scope.id,
            "expires_at": scope.expires_at,
        },
    )


def render_csv(rows):
    return "\n".join(str(row) for row in rows)
