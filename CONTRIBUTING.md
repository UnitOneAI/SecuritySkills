# Contributing to SecuritySkills

Thank you for your interest in evolving SecuritySkills. This project is built by security practitioners, for security practitioners — and we pay bounties for quality contributions.

## Bounty Program

> **⏸️ Paused.** The paid bounty program is temporarily on hold. Contributions are still welcome and will be credited; the tiers below describe the program as it will resume — we'll announce timing on [Discord](https://discord.gg/DKTZzfU9B).

We run a paid bounty program for three types of contributions. All bounties are paid within 48 hours of merge/acceptance.

### Tiers

| Tier | What You Do | Bounty | Time Estimate |
|------|------------|--------|---------------|
| **Reviewer** | Review an existing skill and file structured feedback | $25 per review | 30-60 min |
| **Improver** | Submit a PR that improves an existing skill | $50-150 per merged PR | 1-3 hours |
| **Author** | Write a completely new skill from scratch | $200-500 per merged skill | 3-8 hours |
| **Champion** | Sustained, high-quality contributions over a quarter | $1,000 quarterly bonus | Ongoing |

**Payment methods:** GitHub Sponsors, PayPal, or crypto — your choice. We'll confirm your preferred method when your first contribution is accepted.

### How Bounty Amounts Are Determined

- **Reviewers:** Flat $25 per accepted review that follows the review template
- **Improvers:** $50 for minor improvements (typo fixes, doc updates, small logic tweaks), $100 for moderate improvements (new edge case coverage, false positive reduction), $150 for substantial improvements (rewritten detection logic, major coverage expansion)
- **Authors:** $200 for standard skills (well-known vulnerability class, single language), $350 for intermediate skills (multiple languages/frameworks, nuanced detection), $500 for complex/novel skills (novel detection approach, comprehensive coverage, low false-positive rate)
- **Champions:** Top 3 contributors by quality-weighted contribution count each quarter receive a $1,000 bonus

---

## Quality Rubric

Every submission is scored against this rubric. Minimum **15/23** to qualify for a bounty.

| Criteria | Score Range | What We're Looking For |
|----------|-----------|----------------------|
| **Detection Accuracy** | 0-5 | Does the skill reliably catch what it claims to catch? Tested against known-vulnerable code samples? |
| **False Positive Rate** | 0-5 | Has the skill been tested against benign code? Does it avoid flagging safe patterns? Lower FP rate = higher score |
| **Coverage Breadth** | 0-5 | Does it handle multiple variants, languages, or frameworks where applicable? Edge cases? |
| **Documentation** | 0-5 | Clear description, real-world examples, test cases included? Would another practitioner understand why this skill exists? |
| **Originality** | 0-3 | Is this a novel detection approach? Does it catch something other tools miss? Or is it a well-executed version of a known pattern? |

Scores are assigned by UnitOne maintainers. If you disagree with a score, open a discussion — we're happy to explain our reasoning and adjust if warranted.

---

## Contribution Types

### 1. Skill Review ($25)

Review an existing skill and file a GitHub Issue using the **Skill Review** template.

**What a good review covers:**
- **False positive analysis** — Can you find benign code that this skill incorrectly flags? Provide specific examples.
- **Coverage gaps** — What variants of this vulnerability does the skill miss? Specific languages, frameworks, or patterns.
- **Edge cases** — Unusual but real-world scenarios where the detection or remediation logic breaks.
- **Remediation quality** — Does the proposed fix actually resolve the issue without introducing new problems?
- **Comparison** — How does this compare to equivalent rules in Semgrep, CodeQL, or other tools?

**To submit a review:**
1. Pick a skill from the repository (or check `#bounty-board` in Discord for prioritized reviews)
2. Open a new Issue using the "Skill Review" template
3. Fill in every section of the template
4. Tag your issue with `review`

### 2. Skill Improvement ($50-150)

Improve an existing skill by submitting a Pull Request.

**Types of improvements we value:**
- Reducing false positives (with evidence/test cases)
- Expanding coverage to additional languages or frameworks
- Improving detection logic for edge cases
- Better remediation approaches
- Adding test cases for existing skills

**To submit an improvement:**
1. Fork the repo and create a branch named `improve/[skill-name]-[brief-description]`
2. Make your changes
3. Add evidence demonstrating the improvement, such as minimal vulnerable and benign examples in the PR description or, once a test harness exists, repo fixtures
4. Open a PR using the "Skill Improvement" template
5. In the PR description, clearly explain what was wrong and what you fixed

### 3. New Skill ($200-500)

Author a completely new security skill from scratch.

**Before you start writing:**
- Check existing skills to avoid duplicates
- Check open Issues for requested skills (these are pre-approved topics)
- If your idea isn't listed, open a "New Skill Proposal" Issue first — we'll confirm it's in scope before you invest time

**Skill structure:**
```
skills/
  [category]/
    [skill-name]/
      SKILL.md            # Canonical skill entrypoint
      *.md                # Optional sibling reference files for long detail
```

`SKILL.md` is the only required skill definition file. Do not submit `skill.yaml`
or a per-skill `README.md` as the primary definition. If guidance would make
`SKILL.md` exceed roughly 500 lines, keep the entrypoint lean and move detailed
patterns, benchmark checklists, or language-specific guidance into sibling
Markdown files that are linked from `SKILL.md`.

**To submit a new skill:**
1. Fork the repo and create a branch named `new-skill/[skill-name]`
2. Follow the skill structure above
3. Include at least 3 vulnerable examples and 3 benign examples in the PR description or, once a test harness exists, repo fixtures
4. Open a PR using the "New Skill" template
5. Be prepared for review feedback — most new skills go through 1-2 revision cycles

---

## Skill Format Reference

Each skill is a directory at `skills/<domain>/<skill-name>/` with `SKILL.md` as
the canonical entrypoint. The file starts with YAML frontmatter, followed by
Markdown sections that define when to use the skill, what to detect, hard rules,
remediation, verification, gotchas, and references.

### `SKILL.md` frontmatter

```yaml
---
name: descriptive-skill-name             # kebab-case, matches the directory
description: >                           # what it does + when it auto-invokes
  Reviews a target for a specific security outcome...
tags: [appsec, review]                   # domain + activity keywords
role: [security-engineer, appsec-engineer]
phase: [build, review]
frameworks: [OWASP-ASVS-4.0.3, CWE]      # real framework IDs only
difficulty: intermediate                 # beginner | intermediate | advanced
time_estimate: "30-60min"
version: "1.0.0"
author: your-github-handle
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---
```

Use [SKILL_TEMPLATE.md](SKILL_TEMPLATE.md) as the source of truth for the
required body sections and submission checklist. The machine-readable
frontmatter contract lives in [schemas/skill.schema.json](schemas/skill.schema.json)
and is enforced by CI. Run it locally before opening a PR:

```bash
ruby scripts/validate_skill_schema.rb
```

If your contribution includes skill test fixtures, also run:

```bash
ruby scripts/test_skill_fixtures.rb
```

---

## Getting Started

1. **Join Discord:** [discord.gg/DKTZzfU9B](https://discord.gg/DKTZzfU9B) — check `#bounty-board` for prioritized work
2. **Browse existing skills** to understand the format and quality bar
3. **Pick your first contribution** — we recommend starting with a Review ($25) to get familiar
4. **Ask questions** in `#general` on Discord or open a GitHub Discussion — we're responsive

## Code of Conduct

Be respectful, constructive, and specific. Security is a field where precision matters — back up claims with evidence and test cases. We welcome contributors of all experience levels.

## Dispute Resolution

If you disagree with a bounty decision (rejection, tier assignment, or score), open a Discussion thread tagged `bounty-dispute`. Maintainers will respond within 72 hours with detailed reasoning. We aim to be fair and transparent.

## License

By contributing, you agree that your contributions will be licensed under the same license as this repository. You retain credit — your GitHub handle is permanently recorded in the skill metadata.
