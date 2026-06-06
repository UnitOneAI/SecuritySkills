# Gateway Rate Limit Evidence

This fixture should not be reported as confirmed API4 solely because the
application code lacks local rate-limit middleware.

| Layer | Evidence | Result |
| --- | --- | --- |
| Application | Routes call authenticated handlers only | Rate limit not local |
| Gateway | Kong route `orders-list` enforces `60 requests/minute/user` | Protected at edge |
| Deployment | Kubernetes NetworkPolicy only permits traffic from Kong to app pods | Gateway bypass not evidenced |

Expected classification: `Present at Gateway`, not a confirmed missing rate
limit. If gateway bypass is possible or route mapping is incomplete, classify
the missing evidence explicitly instead of reporting a confirmed finding.
