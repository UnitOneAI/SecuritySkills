---
name: js-unsafe-recursive-merge-prototype-pollution
expected: vulnerable
---

# Unsafe Recursive Merge Prototype Pollution

This fixture should be flagged because untrusted request body keys flow into a recursive object merge without rejecting `__proto__`, `prototype`, or `constructor`.

```js
function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === "object") {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }

  return target;
}

app.post("/api/preferences", express.json(), (req, res) => {
  merge(req.user.preferences, req.body);
  res.json({ ok: true });
});
```

Attack example:

```json
{
  "__proto__": {
    "isAdmin": true
  }
}
```

Expected finding evidence:

| Field | Value |
|---|---|
| Object Write Source | `req.body` |
| Merge or Assignment Sink | Recursive `merge(target, source)` with `target[key] = ...` |
| Dangerous Key Handling | Missing rejection for `__proto__`, `prototype`, and `constructor` |
| Privileged Fields Blocked | Not shown; inherited `isAdmin` can influence downstream checks |
| Schema or DTO Evidence | None |
