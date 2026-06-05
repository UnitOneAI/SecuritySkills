# SAST Fixture Evidence

These compact fixtures support `sast-config` reviews by giving rule authors
known vulnerable and known benign code paths to exercise before enforcing SAST
rules in CI.

Expected use:

- `vulnerable/python_command_injection.py`: true positive for user-controlled
  command execution flowing into a shell sink.
- `benign/python_validated_command.py`: true negative for validated input passed
  as an argument array without a shell.
- `vulnerable/js_raw_sql_route.js`: true positive for request data interpolated
  into raw SQL.
- `benign/js_parameterized_query_route.js`: true negative for the same request
  shape flowing through a parameterized query.

Review reports should cite the fixture path, expected result, rule or query id,
and the scan output used to prove true-positive and true-negative behavior.
