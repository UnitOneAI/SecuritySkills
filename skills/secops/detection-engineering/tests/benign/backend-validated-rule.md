# Benign: Backend-Validated Detection Rule

## Scenario

A Sigma rule has passed lint, converted successfully to the target backend with an explicit field mapping pipeline, and matched expected positive and benign fixtures.

## Sample Evidence

```text
rule=proc_creation_win_powershell_encoded_command.yml
target_backend=sentinel
mapping_pipeline=sigma_config_sentinel.yml
conversion_command=sigma convert -t sentinel -p sigma_config_sentinel.yml rule.yml
conversion_result=pass
true_positive_fixture=atomic_t1059_001_encoded_command.json result=1 match
benign_fixture=sccm_encoded_command.json result=0 matches
deployment_readiness=ready_for_test_mode
```

## Expected Handling

- Treat the rule as tested for the stated backend and mapping pipeline.
- Preserve conversion command, mapping config, fixture names, and results in the output report.
- Keep production readiness separate from test-mode readiness until live telemetry performance is reviewed.
