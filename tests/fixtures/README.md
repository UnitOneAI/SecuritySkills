# Skill Fixture Tests

Fixture cases live under:

```text
tests/fixtures/<skill-id>/<case-id>/
```

Each case must include a `manifest.yaml`:

```yaml
skill: secure-code-review
case_id: hardcoded-secret
kind: vulnerable
target: sample.cs
expected_findings:
  - id: hardcoded-secret
    severity: high
    cwe: CWE-798
    evidence_contains: 'Password = "example"'
```

Required manifest fields:

- `skill`: must match the `<skill-id>` directory.
- `case_id`: must match the `<case-id>` directory.
- `kind`: `vulnerable` or `benign`.
- `target`: relative path to a file inside the case directory.
- `expected_findings`: array of expected structured findings.

Each expected finding must include `id`, `severity`, `evidence_contains`, and
either `cwe` or `framework`. Benign cases must use `expected_findings: []`.

Run the fixture harness locally with:

```bash
ruby scripts/test_skill_fixtures.rb
```

The `_example` fixture is intentionally tiny. It only keeps the harness and CI
executable until real per-skill fixtures are added.
