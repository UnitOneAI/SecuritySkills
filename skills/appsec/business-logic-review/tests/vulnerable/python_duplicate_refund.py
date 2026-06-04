def refund_order(order, user, payment_provider):
    if order.user_id != user.id:
        raise PermissionError("not owner")

    if order.payment_status == "paid":
        payment_provider.refund(order.payment_id, order.total)
        order.refund_status = "refunded"
        order.save()
