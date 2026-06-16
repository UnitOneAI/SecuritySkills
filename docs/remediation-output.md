# Remediation Output Fields

SecuritySkills fix recommendations should be emitted as structured remediation
items under each finding in the normalized JSON envelope documented in
[`docs/normalized-json-output.md`](normalized-json-output.md). Every remediation
item must include:

- `guidance`: concrete remediation steps or patch guidance.
- `confidence`: `low`, `medium`, or `high` confidence that the recommendation is correct for the observed evidence.
- `blast_radius`: the expected scope of systems, files, users, integrations, data, or workflows affected by the change.
- `behavior_change_risk`: `low`, `medium`, or `high` risk that the fix changes intended behavior.
- `test_strategy`: a structured validation plan that explains what proves the issue is fixed.

`test_strategy` must include a `summary` and at least one of:

- `recommended_tests`: tests the user or agent should run when the remediation
  recommends a fix but does not generate test files.
- `generated_tests`: test files or cases produced as part of the remediation.

Each test entry must state the test type, purpose, command or manual check, and
expected result. Generated tests must also identify the test file path. The goal
is to make every fix recommendation falsifiable: the output should say which
test proves the issue is fixed, not only how to change the code.

Example:

```yaml
remediations:
  - guidance: "Reject untrusted redirect targets unless they resolve to an allowed relative path."
    confidence: high
    blast_radius: "Redirect handling in the login callback only."
    behavior_change_risk: medium
    test_strategy:
      summary: "Proves external redirect targets are blocked while relative paths still work."
      recommended_tests:
        - name: "Reject external next URL"
          type: integration
          purpose: "Confirms the vulnerable open-redirect input no longer succeeds."
          command: "bundle exec rspec spec/requests/login_redirect_spec.rb"
          expected_result: "External next=https://evil.example is rejected or replaced with a safe default."
      generated_tests:
        - path: "spec/requests/login_redirect_spec.rb"
          type: regression
          purpose: "Covers the blocked external redirect and allowed internal redirect cases."
          command: "bundle exec rspec spec/requests/login_redirect_spec.rb"
          expected_result: "All login redirect regression examples pass."
```

The machine-readable JSON schema lives in
[`schemas/finding.schema.json`](../schemas/finding.schema.json).
