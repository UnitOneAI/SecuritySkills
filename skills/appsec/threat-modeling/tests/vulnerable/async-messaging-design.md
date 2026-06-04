# Async Messaging Threat Modeling Test Scenario

Use this scenario to verify that the threat-modeling skill captures asynchronous queue trust boundaries, duplicate delivery, idempotency, DLQ handling, and consumer-side authorization.

## Design Under Review

The Checkout API publishes an `orders.created` event to an Amazon SQS standard queue. The event contains `order_id`, `user_id`, `amount`, `shipping_address`, and producer-provided authorization claims. A Fulfillment Worker consumes the event, captures payment, updates order state, and creates a shipment.

The queue uses at-least-once delivery. The Fulfillment Worker does not store processed message IDs or use an idempotency key. If processing fails five times, the message moves to a dead-letter queue. A support role can redrive messages from the DLQ to the source queue without a separate approval or audit event.

## Expected Skill Coverage

The threat model should produce a Queue Evidence Matrix row for `orders.created` that identifies:

- Checkout API as producer and Fulfillment Worker as consumer.
- At-least-once delivery semantics.
- Missing idempotency or replay guard before payment capture and shipment creation.
- Consumer trust in producer-provided authorization claims instead of a current authorization check.
- PII in the message payload through `shipping_address`.
- DLQ redrive access that lacks explicit approval and audit evidence.

The threat register should include findings for:

- Spoofing: unauthorized producers publishing trusted `orders.created` events.
- Tampering: modified message fields such as `amount`, `user_id`, or `shipping_address`.
- Repudiation: unaudited retry and DLQ redrive actions.
- Information disclosure: sensitive payload data retained in the DLQ.
- Denial of service: poison messages or retry storms exhausting consumers.
- Elevation of privilege: a compromised producer triggering privileged downstream actions because the consumer does not re-authorize.
