<!--
SecuritySkills — Skill Template (v2)
Copy this file to skills/<domain>/<skill-name>/SKILL.md and fill it in.
This template matches the format ALL 45 shipped skills use. Replace the
frontmatter values and each section; delete these comments before submitting.
Domains: appsec · ai-security · identity · cloud · network · secops ·
         compliance · devsecops · vuln-management · incident-response
-->
---
name: my-skill-name                       # kebab-case, MUST match the directory name
description: >                            # 2-4 sentences: what it does + when it auto-invokes.
  One-line summary of the security outcome, then the trigger conditions
  ("Auto-invoked when the user ... or asks ..."). This is what an agent reads
  to decide whether to load the skill, so lead with behavior, not jargon.
tags: [appsec, review]                    # domain + activity keywords (see index.yaml tag_vocabulary)
role: [security-engineer, appsec-engineer]# role bundles that should include this skill
phase: [build, review]                    # design | build | deploy | operate | respond | review | ...
frameworks: [OWASP-ASVS-4.0.3, CWE]       # frameworks you cite — REAL control IDs only, no invented refs
difficulty: intermediate                  # beginner | intermediate | advanced
time_estimate: "30-60min"
version: "1.0.0"
author: your-handle                       # GitHub handle or agent session ID
license: MIT
allowed-tools: Read, Grep, Glob           # tools the skill may use
injection-hardened: true                  # set true once reviewed against OWASP LLM01:2025
argument-hint: "[target-file-or-directory]"
# context: fork                           # optional
---

# <Skill Name> — <Methodology / Framework>

## 1. When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when:

- **<Trigger 1>** — concrete situation that should activate the skill.
- **<Trigger 2>** — another concrete situation.
- **<Trigger 3>** — ...

## 2. What to Detect

What signals tell the agent this issue is present? Be precise — give patterns
the agent can match, not just descriptions.

| Signal | Pattern | Confidence |
|---|---|---|
| Regex | `(api_key\|secret\|token)\s*=\s*['"][A-Za-z0-9]{16,}['"]` | HIGH |
| Structural | `.env` committed alongside source | HIGH |
| Behavioral | agent reads from env, then writes value into a generated file | MEDIUM |

> For long pattern libraries, put them in a sibling reference file (see §7) and link here.

## 3. Rules (Constraints)

Hard rules only — falsifiable and enforceable. No "consider" / "may" language.

- **MUST** map every finding to a real control ID from a `frameworks` entry.
- **MUST NOT** emit a control ID that doesn't resolve in the cited framework.
- **MUST** <skill-specific hard rule>.
- **MUST NOT** <skill-specific hard rule>.

## 4. Remediation

What the agent emits or changes when this fires. Keep complex logic in a
reference/script file (§7), not inline. Every fix recommendation must include
remediation guidance, confidence, blast radius, behavior-change risk, and a
test strategy that names what proves the issue is fixed. If this skill can
modify code or configuration, classify each remediation path using the repo-level
`docs/fixer-policy.md` before applying changes.

**Before (vulnerable):**
```
<minimal vulnerable example>
```

**After (remediated):**
```
<what the agent should produce>
```

**Fix recommendation output:**
```yaml
remediations:
  - guidance: "<concrete remediation steps or patch guidance>"
    confidence: high                    # low | medium | high
    blast_radius: "<affected files, users, systems, integrations, or workflows>"
    behavior_change_risk: medium        # low | medium | high
    test_strategy:
      summary: "<what proves this remediation fixed the finding>"
      recommended_tests:
        - name: "<test name>"
          type: regression              # static | unit | integration | e2e | regression | manual
          purpose: "<vulnerable behavior or regression this test proves>"
          command: "<command or manual check to run>"
          expected_result: "<binary passing result>"
      generated_tests:
        - path: "<path/to/generated_test_file>"
          type: regression              # static | unit | integration | e2e | regression
          purpose: "<vulnerable behavior or regression this generated test proves>"
          command: "<command that runs the generated test>"
          expected_result: "<binary passing result>"
```

## 5. Verification (falsifiable)

The skill is not "done" until this passes — binary, not aspirational.

| | |
|---|---|
| **Input** | minimal vulnerable case the agent can test against |
| **Expected output** | what the remediated version produces |
| **Pass condition** | specific + binary |
| **Fail condition** | specific + binary |

Step-by-step confirmation the fix held:
1. Re-scan the modified file with the §2 pattern.
2. Confirm no matches.
3. Confirm intended behavior is unchanged.

## 6. Gotchas (self-improvement loop)

Minimum 2 false positives + 1 precision trap on creation; add more after each run.
This section is how the skill gets sharper over time.

**False positives**
- **Pattern:** <what trips it> — **Why:** <context> — **Suppress:** <guidance>
- **Pattern:** ... — **Why:** ... — **Suppress:** ...

**Precision traps**
- **Trap:** where the remediation breaks behavior — **Mitigation:** how to preserve intent.

**Do NOT flag:** example.com URLs, `YOUR_API_KEY_HERE` placeholders, clearly mocked test data.

## 7. References (progressive disclosure)

Keep this `SKILL.md` lean. When guidance exceeds ~500 lines, split detail into
sibling files in this directory and link them — the agent loads them on demand:

```
skills/<domain>/<skill-name>/
├── SKILL.md                 ← this file (lean entrypoint)
├── patterns.md              ← full detection-pattern library
└── <language>.md            ← language/framework-specific guidance
```

- [patterns.md](patterns.md) — extended detection patterns
- [<language>.md](<language>.md) — language-specific rules

---

## Submission checklist (delete before submitting)

- [ ] Directory is `skills/<domain>/<skill-name>/`; entrypoint is `SKILL.md`
- [ ] Frontmatter complete; `name` matches the directory
- [ ] Every framework ID is real and resolves (no invented control numbers)
- [ ] At least one machine-matchable detection signal (regex / structural)
- [ ] Rules are hard constraints (no "consider"/"may")
- [ ] Before/after remediation example present
- [ ] Every fix recommendation includes `guidance`, `confidence`, `blast_radius`, `behavior_change_risk`, and `test_strategy`
- [ ] Every `test_strategy` includes a summary plus recommended tests, generated tests, or both
- [ ] Falsifiable verification test defined (binary pass/fail)
- [ ] Gotchas: ≥2 false positives + ≥1 precision trap
- [ ] `SKILL.md` stays lean; long detail moved to reference files
- [ ] `injection-hardened: true` only after reviewing the body against OWASP LLM01:2025
- [ ] Commit message: `feat(skill): <skill-name> — <what it detects>`

*SecuritySkills Skill Template v2 — UnitOne.ai · matches the format all shipped skills use.*
