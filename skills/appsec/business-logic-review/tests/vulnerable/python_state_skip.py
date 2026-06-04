def update_order_status(order, requested_status, actor):
    if actor.id != order.user_id:
        raise PermissionError("not owner")

    order.status = requested_status
    order.save()
