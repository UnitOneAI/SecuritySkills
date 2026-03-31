---
name: Skill Review ($25 Bounty)
about: Review an existing skill — analyze false positives, coverage gaps, and edge cases
title: "[REVIEW] "
labels: review, bounty
assignees: ''
---

## Skill Being Reviewed
**Skill name:**
**Skill path:** `skills/[category]/[skill-name]/`

## False Positive Analysis
<!-- Can you find benign code that this skill incorrectly flags? Provide specific code examples. -->

**Benign code that triggers a false positive:**
```
(paste code here)
```

**Why this is a false positive:**


## Coverage Gaps
<!-- What variants of this vulnerability does the skill miss? Be specific about languages, frameworks, or patterns. -->

**Missed variant 1:**
```
(paste vulnerable code the skill misses)
```
**Why it should be caught:**

**Missed variant 2:**
```
(paste vulnerable code the skill misses)
```
**Why it should be caught:**

## Edge Cases
<!-- Unusual but real-world scenarios where the detection or remediation logic breaks. -->


## Remediation Quality
<!-- Does the proposed fix actually resolve the issue? Could it introduce new problems? -->

- [ ] Fix resolves the vulnerability
- [ ] Fix doesn't introduce new security issues
- [ ] Fix doesn't break functionality
- **Issues found:**

## Comparison to Other Tools
<!-- How does this compare to equivalent rules in Semgrep, CodeQL, Snyk, or other SAST tools? -->

| Tool | Catches this? | Notes |
|------|:---:|-------|
| Semgrep | Yes/No/Partial | |
| CodeQL | Yes/No/Partial | |
| Other: | Yes/No/Partial | |

## Overall Assessment
<!-- Your summary: what's good about this skill, what needs work, and prioritized recommendations. -->

**Strengths:**

**Needs improvement:**

**Priority recommendations:**
1.
2.
3.

## Bounty Info
- [ ] I have read and agree to the [CONTRIBUTING.md](../../CONTRIBUTING.md) bounty terms
- **Preferred payment method:** GitHub Sponsors / PayPal / Crypto
