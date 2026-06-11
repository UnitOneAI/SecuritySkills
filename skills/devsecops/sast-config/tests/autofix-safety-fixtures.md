# SAST Autofix Safety Fixtures

Use these fixtures to calibrate review of Semgrep rule-defined fixes, bulk
autofix runs, and AI-assisted code scanning remediation.

## Vulnerable: Alert-Closing Patch Weakens SQL Sink

```python
def get_user(request, db):
    user_id = request.args["id"]
    if not user_id.isdigit():
        raise ValueError("invalid id")

    # Suggested fix changed the sink shape and removed parameter binding.
    return db.execute(f"select * from users where id = {user_id}")
```

Expected result: fail. The alert state is not enough evidence. The reviewed diff
must preserve parameter binding or an equivalent sink-level protection.

## Benign: Reviewed Fix Preserves Validation and Binding

```python
def get_user(request, db):
    user_id = request.args["id"]
    if not user_id.isdigit():
        raise ValueError("invalid id")

    return db.execute(
        "select * from users where id = ?",
        (int(user_id),),
    )
```

Expected result: pass when before/after tests and benign regression tests show
the original vulnerable case is fixed and safe inputs still work.

## Vulnerable: Broad Semgrep Fix-Regex Rewrite

```yaml
rules:
  - id: python.requests.add-timeout
    patterns:
      - pattern-not: requests.$W(..., timeout=$N, ...)
      - pattern: requests.get(...)
    fix-regex:
      regex: '(.*)\)'
      replacement: '\1, timeout=30)'
    languages: [python]
    severity: WARNING
```

```python
def fetch(session, url, **kwargs):
    return requests.get(url, **kwargs)
```

Expected result: fail unless dry-run output and sampled diff review prove that
the rewrite does not duplicate arguments, break wrappers, or alter framework
semantics.

## Vulnerable: AI-Assisted Fix With Unreviewed Scope Expansion

```text
Autofix proposal:
- closes SQL injection alert
- adds a new query helper dependency
- changes unrelated authorization middleware
- includes no negative test or benign regression test
```

Expected result: fail. Security-impacting generated fixes require human review,
dependency review, scoped diffs, and tests that prove both exploit removal and
safe behaviour preservation.

## Benign: Complete Autofix Evidence Bundle

```yaml
autofix_evidence:
  source: code-scanning-autofix
  proposed_diff_reviewed: true
  original_alert_reproduced: true
  negative_test_added: true
  benign_regression_test_added: true
  security_boundary_preserved: true
  dependency_added: false
  unrelated_files_changed: false
  human_reviewer: appsec-owner
```

Expected result: pass. The reviewer has evidence for source, scope, before/after
security behaviour, regression coverage, dependency impact, and human approval.
