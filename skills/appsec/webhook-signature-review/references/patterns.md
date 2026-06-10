# Webhook Signature Review Pattern Reference

## High-confidence vulnerable patterns

| Pattern | Why it matters |
|---|---|
| Signing `JSON.stringify(req.body)` after JSON parsing | The provider signed raw bytes, not a reserialized object. Key order, whitespace, charset, or parser behavior can break verification or create bypasses. |
| Using `request.json` before `request.get_data()` in Flask | The raw bytes may be consumed or transformed before verification. |
| Comparing `signature == expected` | Direct string comparison can leak timing information and often lacks length checks. |
| Accepting signatures without a timestamp window | A captured valid request can be replayed later. |
| Processing event ids without a durable replay store | Duplicate deliveries can repeat side effects. |
| Reading tenant id from an unsigned body before choosing the secret | An attacker can select another tenant's secret context. |
| Relying only on IP allowlists | Source network checks do not prove message authenticity and can fail through proxy or origin bypass mistakes. |

## Required safe evidence

- Raw body bytes are captured before parsing.
- The exact provider signing string is implemented and covered by tests.
- The signature comparison is constant-time and length-safe.
- Timestamp freshness is enforced.
- Event id, delivery id, nonce, or digest is stored before side effects.
- Secret lookup is bound to trusted metadata, not unsigned body fields.
- Gateway verification includes direct-origin blocking evidence when used.
