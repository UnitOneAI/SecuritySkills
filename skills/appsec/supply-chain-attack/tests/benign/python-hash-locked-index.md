# Benign Fixture: Python Single Index With Hashes

```txt
# requirements.txt
--index-url https://pypi.internal.example/simple/
--require-hashes
company-auth-lib==1.2.0 \
    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111
requests==2.32.3 \
    --hash=sha256:2222222222222222222222222222222222222222222222222222222222222222
```

Expected decision:

- Do not flag `SCA-ATTACK-02`; the install uses a single authoritative index rather than public fallback.
- Do not flag missing hash evidence; hash-checking mode is explicit.
