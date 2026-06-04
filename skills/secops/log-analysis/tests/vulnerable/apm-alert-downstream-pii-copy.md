# Vulnerable Test: APM And Alert Payload Reintroduce PII

## Scenario

Application logs redact request bodies before SIEM ingestion, but the same error path sends:

- APM breadcrumb with `user.email`, `shippingAddress`, and `Authorization` header.
- Alert notification summary that includes the raw exception context.
- Ticket system custom field populated from the unredacted APM event.
- No evidence that the APM scrubber, alert template, or ticket field mapping removes sensitive values.

## Expected Result

The skill should flag a privacy-control finding with reason code `downstream-copy`. The report should explain that SIEM redaction alone is insufficient when APM, alert, or ticket destinations reintroduce raw personal data or credentials.

## Regression Covered

Log analysis must trace sensitive data across downstream observability and case-management copies, not only the primary SIEM index.
