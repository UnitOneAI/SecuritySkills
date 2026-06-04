def refund_order(order, user, request_id, refund_repository, payment_provider):
    if order.user_id != user.id:
        raise PermissionError("not owner")
    if order.status not in {"paid", "returned"}:
        raise ValueError("order is not refundable")

    existing = refund_repository.find_by_request(order.id, user.id, request_id)
    if existing:
        return existing.result

    refund = refund_repository.reserve(order.id, user.id, request_id, order.payment_id, order.total)
    refund.result = payment_provider.refund(order.payment_id, order.total)
    refund_repository.mark_complete(refund)
    return refund.result
