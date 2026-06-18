# PR Intake Loop

Use this runbook as the `/loop` procedure for incoming pull requests against
`UnitOneAI/SecuritySkills`. The loop turns each unprocessed PR into tracked
Linear work, reviews it, verifies it, and either merges it or leaves clear
feedback.

## Loop Contract

Repeat until there are no actionable open PRs:

1. Discover incoming PRs.
2. Create or link a Linear issue for each PR.
3. Pick one PR and move the Linear issue to `In Progress`.
4. Review legitimacy and scope.
5. Verify locally and with GitHub checks.
6. Merge only when the change is legitimate, tested, and branch policy is
   satisfied or explicitly overridden by an administrator.
7. Update Linear and continue to the next PR.

Stop and ask for guidance when a PR requires product/security design decisions,
changes release policy, weakens controls, rewrites unrelated code, or cannot be
verified with the available environment.

## Discovery

List open PRs:

```bash
gh pr list --repo UnitOneAI/SecuritySkills --state open --json number,title,author,headRefName,baseRefName,isDraft,mergeStateStatus,url,labels,updatedAt
```

Skip PRs that are already represented by a Linear issue linked in the PR body,
branch name, comments, or Linear attachments. For every untracked PR, create a
Linear issue in the `SecuritySkills Linear Roadmap` project.

Linear issue template:

```markdown
Incoming PR review for <PR title>

GitHub PR: <PR URL>
Author: <GitHub author>
Branch: <head branch>
Base: <base branch>

Loop tasks:
- Review legitimacy and scope.
- Run local verification.
- Check GitHub CI.
- Merge, request changes, or close with rationale.
```

Suggested Linear priority:

- `Urgent`: security-sensitive fix, broken main, CI/release failure.
- `High`: substantive repo behavior, schema, workflow, or skill change.
- `Normal`: docs, examples, low-risk fixtures.
- `Low`: typo-only or cosmetic cleanup.

## Review Gate

Before touching files or merging, inspect:

```bash
gh pr view <PR> --repo UnitOneAI/SecuritySkills --json number,title,author,body,baseRefName,headRefName,isDraft,mergeStateStatus,commits,files,labels,url
gh pr diff <PR> --repo UnitOneAI/SecuritySkills
```

A PR is legitimate only when:

- The intent is clear and in scope for SecuritySkills.
- The diff matches the PR description.
- It does not weaken security guidance, validation, CI, release integrity, or
  review gates without a strong documented reason.
- It does not include unrelated refactors or generated churn.
- It preserves existing schema and fixture contracts unless the PR explicitly
  updates those contracts and tests.
- It has a reasonable verification path.

If the PR is not legitimate, do not merge. Leave a concise review comment or
Linear note with the blocking reason and move the issue to the appropriate
blocked/review state.

## Local Verification

Check out the PR in an isolated worktree or branch:

```bash
gh pr checkout <PR> --repo UnitOneAI/SecuritySkills
```

Run the standard verification suite:

```bash
ruby scripts/validate_skill_schema.rb
ruby scripts/validate_index.rb
ruby scripts/test_skill_fixtures.rb
ruby scripts/generate_quality_scorecard.rb --check
ruby scripts/validate_framework_registry.rb
ruby scripts/validate_framework_registry.rb --stale --max-age-days 365
ruby scripts/validate_codeowners.rb
git diff --check
```

Run targeted checks when touched files require them:

```bash
ruby scripts/test_remediation_fixtures.rb
ruby scripts/validate_ci_cd_examples.rb
ruby -ryaml -e 'YAML.safe_load(File.read(".github/workflows/<workflow>.yml"), permitted_classes: [], aliases: false)'
ruby -rjson -e 'JSON.parse(File.read("schemas/<schema>.json"))'
```

If the PR changes release workflows, framework references, CODEOWNERS, schemas,
or normalized output contracts, include the relevant command output summary in
the Linear issue before merge.

## GitHub Checks

Wait for GitHub checks:

```bash
gh pr checks <PR> --repo UnitOneAI/SecuritySkills --watch
```

Do not merge with failing checks unless the failure is unrelated and the
override is explicitly documented in Linear.

## Merge Gate

Merge only when all are true:

- Linear issue exists and is `In Progress` or `In Review`.
- PR is not draft.
- PR has been reviewed for legitimacy and scope.
- Required local verification passed.
- GitHub checks passed.
- The merge result is expected to preserve main.

Preferred merge:

```bash
gh pr merge <PR> --repo UnitOneAI/SecuritySkills --squash --delete-branch
```

If branch policy blocks the merge after all requirements have passed and the
maintainer has admin rights, use:

```bash
gh pr merge <PR> --repo UnitOneAI/SecuritySkills --squash --delete-branch --admin
```

After merge, verify:

```bash
gh pr view <PR> --repo UnitOneAI/SecuritySkills --json state,mergedAt,mergedBy,url,title
git switch main
git pull --ff-only origin main
```

Then move the Linear issue to `Done` and attach the PR link.

## Change Requests

When a PR should not merge yet:

1. Leave a GitHub review or comment with specific requested changes.
2. Add a Linear comment summarizing the blocker.
3. Move Linear to an appropriate review or blocked state.
4. Continue the loop with the next PR.

Do not rewrite contributor branches unless the maintainer explicitly asks you to
take over the branch. If taking over is approved, preserve contributor commits
where practical and document any force-push risk before acting.

## Loop Prompt

Use this prompt to start the loop:

```text
/loop PR intake for UnitOneAI/SecuritySkills:
1. List open GitHub PRs.
2. For each untracked PR, create or link a Linear issue in SecuritySkills Linear Roadmap.
3. Pick the highest-priority actionable PR.
4. Review scope and legitimacy.
5. Run local verification and GitHub checks.
6. Merge only if legitimate and verified; otherwise request changes with rationale.
7. Update Linear, sync main, and continue until no actionable PRs remain.
If in doubt or if design/security policy is involved, stop and ask me.
```
