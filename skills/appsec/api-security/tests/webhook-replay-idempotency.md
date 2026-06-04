# Webhook replay and idempotency evidence

## Vulnerable: parsed-body signature and replayable side effects

```javascript
app.post('/webhooks/payment', express.json(), async (req, res) => {
  const expected = hmac(JSON.stringify(req.body), process.env.WEBHOOK_SECRET);
  if (expected !== req.header('X-Signature')) return res.sendStatus(401);

  await provisionSubscription(req.body.customerId, req.body.planId);
  res.sendStatus(204);
});
```

Why this should be flagged:

- The signature is computed over reserialized JSON instead of the exact raw body bytes.
- There is no timestamp tolerance, nonce cache, or event ID replay guard.
- Subscription provisioning is non-idempotent and can be repeated by duplicate delivery or replay.

## Benign: raw-body verification plus event ID idempotency

```javascript
app.post('/webhooks/payment', rawBodyMiddleware, async (req, res) => {
  const event = verifyProviderSignature({
    rawBody: req.rawBody,
    signatureHeader: req.header('X-Provider-Signature'),
    toleranceSeconds: 300,
    activeSecrets: [process.env.WEBHOOK_SECRET_CURRENT, process.env.WEBHOOK_SECRET_PREVIOUS],
  });

  const inserted = await webhookEvents.insertIfAbsent({
    provider: 'payment',
    eventId: event.id,
    receivedAt: new Date(),
  });

  if (!inserted) return res.status(200).json({ status: 'duplicate_event' });

  await provisionSubscription(event.data.customerId, event.data.planId);
  res.sendStatus(204);
});
```

Why this should pass:

- Signature verification uses the raw body and provider signature header.
- A bounded timestamp tolerance limits replay.
- The provider event ID is stored before side effects, making duplicate delivery safe.
- Old/new secret overlap is explicit and can be expired during rotation.
