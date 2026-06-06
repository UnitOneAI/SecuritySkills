# Vulnerable Fixture: pip Extra Index Confusion

```txt
# requirements.txt
--extra-index-url https://pypi.internal.example/simple/
company-auth-lib==1.2.0
requests==2.32.3
```

Expected findings:

- `SCA-ATTACK-02` High: `--extra-index-url` lets pip search both public and private indexes, which can select an attacker-controlled higher version for an internal package.
- `SCA-ATTACK-03` Medium: no hash-checking or lock evidence is present for a release install.

Benign contrast: use a single authoritative `--index-url`, private package constraints, and hash-locked release requirements.
