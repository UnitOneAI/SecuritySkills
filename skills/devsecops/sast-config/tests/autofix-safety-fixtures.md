# SAST Autofix Safety Fixtures

Use these fixtures to calibrate review of SAST-generated fixes, Semgrep
rule-defined fixes, and code scanning autofix suggestions.

## Vulnerable: Autofix Removes Existing Validation

```python
def get_user(request, db):
    user_id = request.args["id"]
    if not user_id.isdigit():
        raise ValueError("invalid id")

    # Unsafe autofix changed this to string interpolation and removed the
    # parameter binding that the scanner originally expected.
    return db.execute(f"select * from users where id = {user_id}")
```

Expected result: fail. The alert may disappear if the scanner pattern no longer
matches, but the fix changed the data-access pattern and relies on a validation
guard that can drift away from the sink.

## Benign: Reviewed Fix Preserves Security Boundary

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

Expected result: pass. The fix preserves validation and uses parameter binding at
the sink.

## Vulnerable: Semgrep Fix-Rewrite Changes Wrapper Semantics

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

Expected result: needs manual review. A broad regex fix can create duplicate
timeout arguments or change wrapper behavior when timeout is already supplied
through `**kwargs`.

## Benign: Autofix Evidence Bundle

```yaml
autofix_evidence:
  source: semgrep fix-regex
  dry_run_diff_reviewed: true
  negative_test_added: true
  benign_regression_test_added: true
  unrelated_files_changed: false
  dependency_added: false
  human_reviewer: appsec-owner
```

Expected result: pass. The reviewer has evidence that the suggested fix was
scoped, tested, and approved before application.
