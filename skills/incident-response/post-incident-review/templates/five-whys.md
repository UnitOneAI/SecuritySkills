# 5 Whys Template

Extracted from the post-incident-review SKILL.md.

```
Incident: [Description of what happened]

Why 1: Why did [incident impact] occur?
  -> Because [proximate cause]

Why 2: Why did [proximate cause] occur?
  -> Because [contributing factor]

Why 3: Why did [contributing factor] exist?
  -> Because [process/system gap]

Why 4: Why did [process/system gap] exist?
  -> Because [organizational/design factor]

Why 5: Why did [organizational/design factor] exist?
  -> Because [root cause]

Root Cause: [Systemic root cause statement]
```

## Guidelines

- Each answer must be factual and verifiable, not speculative
- Stop when you reach a cause that is within the organization's control to change
- If the chain branches (multiple contributing factors at one level), follow each branch
- Avoid stopping at "human error" -- always ask what system condition enabled the error
