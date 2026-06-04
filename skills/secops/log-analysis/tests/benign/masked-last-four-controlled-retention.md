# Benign Test: Masked Last-Four Field With Controlled Retention

## Scenario

An application emits payment-support logs with:

- `card_last4=4242`
- Raw PAN rejected before application log emission.
- Collector pipeline drops `request.body.cardNumber` and records a transformed sample event.
- SIEM index retention is 30 days with access limited to the fraud operations role.
- Alert and ticket templates include `card_last4` only and do not copy raw request bodies.

## Expected Result

The skill should not report raw payment-data leakage solely because `card_last4` resembles payment data. It should record the field as controlled when source rejection, downstream redaction, access scope, and retention evidence are available.

## Regression Covered

Identifier-like masked fields should not create false positives when raw values are rejected before ingestion and all downstream copies remain masked.
