# SecuritySkills

> An open library of security detection and remediation skills. Each skill defines **what to detect**, **how to verify it**, and **how to fix it** — executable security knowledge for the age of AI-generated code.

Built by [UnitOne](https://unitone.ai) and the security community.

---

## Earn Bounties

We pay security practitioners to review, improve, and author skills. Your expertise makes this library better — and we compensate you for it.

| Contribution | Bounty | Time |
|-------------|--------|------|
| **Review** a skill (structured feedback on FPs, gaps, edge cases) | $25 | 30-60 min |
| **Improve** a skill (better detection, broader coverage) | $50-150 | 1-3 hrs |
| **Author** a new skill from scratch | $200-500 | 3-8 hrs |
| **Champion** bonus (top 3 contributors/quarter) | $1,000 | Ongoing |

Paid within 48 hours of merge. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full rubric, templates, and rules.

**Get started:**
1. Join [Discord](https://discord.gg/DKTZzfU9B) and check `#bounty-board`
2. Pick a skill to review or improve (or propose a new one)
3. Follow the templates in [CONTRIBUTING.md](CONTRIBUTING.md)
4. Submit and get paid

---

## What Are Security Skills?

A security skill is a structured unit of security knowledge:

```
Detection  →  "This code pattern is vulnerable to SQL injection"
Verification →  "Here's how to confirm it's a true positive, not a false alarm"
Remediation →  "Here's the verified fix that resolves it without breaking anything"
```

Traditional SAST tools stop at detection. Skills go further — they verify and fix, reducing mean time to remediate from **84 days** to **minutes**.

## Repository Structure

```
skills/
  injection/          # SQL injection, command injection, LDAP injection, etc.
  xss/                # Cross-site scripting variants
  auth/               # Authentication and authorization flaws
  crypto/             # Cryptographic misuse
  secrets/            # Hardcoded credentials, API keys, tokens
  config/             # Security misconfigurations
  dependency/         # Vulnerable dependency detection
  ...
```

Each skill contains:
- `skill.yaml` — Detection patterns, remediation logic, metadata
- `README.md` — Human-readable explanation and examples
- `tests/vulnerable/` — Code that should trigger the skill
- `tests/benign/` — Code that should NOT trigger (false positive checks)

## Who We're Looking For

- **AppSec engineers** who write SAST/DAST rules and know what actually triggers in production
- **Open source contributors** familiar with Semgrep, CodeQL, Nuclei, or similar tools
- **Security researchers** who find vulnerabilities and understand how to fix them

No prior open-source contribution experience required. Start with a review ($25) to get familiar with the format.

## Community

- **Discord:** [discord.gg/DKTZzfU9B](https://discord.gg/DKTZzfU9B) — bounty coordination, discussions, support
- **GitHub Discussions:** For longer-form technical conversations
- **Issues:** For bug reports, skill requests, and reviews

## License

[License details here]

## About UnitOne

[UnitOne](https://unitone.ai) is building a Security State Layer for agentic development — deterministic security remediation that reduces MTTR from 84 days to under 10 minutes. Founded by engineers from Microsoft, Oracle, Meta, and Lyft.
