---
name: js-strict-dto-object-update
expected: benign
---

# Strict DTO Object Update

This fixture should not be flagged as prototype pollution or mass assignment. The route parses the request body through a strict schema, rejects unknown fields, and applies only allowlisted profile fields.

```ts
import { z } from "zod";

const profilePatchSchema = z.object({
  displayName: z.string().max(80).optional(),
  timezone: z.string().max(64).optional(),
}).strict();

app.patch("/api/profile", requireAuth, async (req, res) => {
  const patch = profilePatchSchema.parse(req.body);

  await users.updateProfile(req.user.id, {
    displayName: patch.displayName,
    timezone: patch.timezone,
  });

  res.sendStatus(204);
});
```

Expected evidence:

| Field | Value |
|---|---|
| Object Write Source | `req.body` |
| Merge or Assignment Sink | Explicit allowlisted update |
| Dangerous Key Handling | Unknown keys rejected by `.strict()` |
| Privileged Fields Blocked | No `role`, `isAdmin`, `tenantId`, or `ownerId` fields accepted |
| Schema or DTO Evidence | `profilePatchSchema` on the same path as the update |
