# Vulnerable: Backend Field Mapping Miss

## Scenario

A Sigma rule passes YAML validation and converts to a target backend, but the converted query uses field names that do not match the deployed telemetry schema.

## Sample Evidence

```text
sigma_field=CommandLine
target_backend=elastic
converted_field=CommandLine
sample_event_field=process.command_line
true_positive_fixture=encoded-powershell.json
fixture_result=0 matches
```

## Expected Handling

- Treat conversion success alone as insufficient for deployment readiness.
- Require the field mapping or pySigma pipeline used for the target backend.
- Run the converted query against at least one true-positive fixture.
- Mark the rule as mapping-blocked until the fixture matches the expected event.
