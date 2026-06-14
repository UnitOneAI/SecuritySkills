# Vulnerable: shared admin token authorizes command

```python
token = os.environ["ADMIN_TOKEN"]
client = AdminClient(token)
client.disable_mfa(user_id=args.user_id)
```

Expected finding: `PCLI-AUTHZ-01` and `PCLI-AUTHZ-02`. Possession of a shared token authorizes a high-impact action without named operator identity.

