# Vulnerable: subscription event delivery lacks per-event authorization

This sample should be reported because tenant access is checked only when the subscription starts. Later events are delivered from a shared topic without checking whether the viewer still has access to the tenant or resource.

```javascript
export const resolvers = {
  Subscription: {
    ticketUpdated: {
      subscribe: async (_, { tenantId }, ctx) => {
        await requireTenantMember(ctx.user, tenantId);
        return pubsub.asyncIterator(`ticket-updates`);
      },
      resolve: event => event.ticket,
    },
  },
};
```

Expected finding:

- OWASP API Risk: API1:2023 BOLA.
- Evidence: shared topic and resolver output do not bind each pushed event to tenant and subject authorization.
- Remediation: use tenant-scoped topics or filter each event with current tenant and resource permissions before returning it.
