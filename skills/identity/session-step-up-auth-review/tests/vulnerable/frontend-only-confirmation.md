# Vulnerable: frontend-only confirmation

```tsx
function DeleteAccountButton() {
  const confirmed = window.confirm("Delete account?");
  if (confirmed) {
    return fetch("/api/account/delete", { method: "POST" });
  }
}

app.post("/api/account/delete", requireLogin, deleteAccount);
```

Expected finding: `STEPUP-ENF-01` and `STEPUP-ENF-02`. The sensitive backend mutation has no server-side recent-auth guard.

