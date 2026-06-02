# Vulnerable: Lint-Only Rule Counted as Tested Coverage

## Scenario

A rule is marked as `Tested` in the ATT&CK heatmap because Sigma lint passed, but there are no true-positive and benign fixtures.

## Sample Evidence

```text
rule=proc_creation_win_powershell_encoded_command.yml
sigma_lint=pass
backend_conversion=not_run
true_positive_fixture=missing
benign_fixture=missing
coverage_level=Tested
```

## Expected Handling

- Downgrade coverage to `Theoretical` until backend conversion and fixture testing are complete.
- Require at least one known-bad fixture and one benign fixture for expected false-positive/tuning validation.
- Document validation method and fixture result in the report output.
