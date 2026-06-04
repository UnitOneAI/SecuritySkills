# Vulnerable Test: Error Storm Bypasses Sampling And Captures Full Payloads

## Scenario

Normal production traffic is sampled at 1%, but an exception handler changes behavior during repeated validation failures:

- Debug mode logs the full request and response body for every failed request.
- Panic logging bypasses the structured redaction middleware.
- The SIEM index stores the expanded error events for 180 days.
- No test demonstrates that sampling, truncation, or redaction still applies during retry storms.

## Expected Result

The skill should flag a privacy and retention finding with reason codes `sampling-bypass` and `retention-overrun`. The recommendation should require error-path tests, redaction before panic logging, and data-class-specific retention.

## Regression Covered

Normal-path sampling evidence should not hide error/debug paths that capture full sensitive payloads.
