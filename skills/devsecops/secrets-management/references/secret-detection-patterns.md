# Secret Detection Patterns

These regex patterns are for configuring detection tools (Gitleaks, TruffleHog, detect-secrets). They are NOT for secret extraction.

## API Keys and Tokens

```regex
# AWS Access Key ID (starts with AKIA)
(?:AKIA)[0-9A-Z]{16}

# AWS Secret Access Key (40 chars, base64-like)
(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}

# GitHub Personal Access Token
(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}

# GitLab Personal Access Token
glpat-[A-Za-z0-9\-_]{20,}

# Slack Bot/User OAuth Token
xox[bpors]-[0-9]{10,13}-[A-Za-z0-9-]{20,}

# Generic Bearer Token
[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*

# Generic API Key pattern
(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9]{20,}['"]
```

## Private Keys

```regex
# RSA/DSA/EC/OpenSSH Private Key Headers
-----BEGIN\s(?:RSA|DSA|EC|OPENSSH)\sPRIVATE\sKEY-----

# PGP Private Key
-----BEGIN\sPGP\sPRIVATE\sKEY\sBLOCK-----
```

## Connection Strings and Passwords

```regex
# Database connection strings with embedded passwords
(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@]+@

# Generic password assignment
(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]

# JWT tokens (three base64url segments separated by dots)
eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*
```

## Additional High-Value Patterns

```regex
# Google Cloud Service Account Key (JSON)
(?i)"type"\s*:\s*"service_account"

# Stripe API Key
(?:sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]{20,}

# SendGrid API Key
SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}

# Twilio Account SID / Auth Token
(?:AC[a-f0-9]{32}|SK[a-f0-9]{32})

# Mailgun API Key
key-[A-Za-z0-9]{32}
```
