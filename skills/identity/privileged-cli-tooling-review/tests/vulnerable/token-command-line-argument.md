# Vulnerable: token passed as command-line argument

```bash
node tools/admin-refund.js --token "$ADMIN_TOKEN" --user "$USER_ID" --amount 100
```

Expected finding: `PCLI-CRED-01`. Privileged tokens passed as arguments can leak through shell history, process listings, and job logs.

