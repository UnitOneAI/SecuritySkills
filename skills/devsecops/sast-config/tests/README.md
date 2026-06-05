# SAST Fixture Evidence

These fixtures give reviewers compact true-positive and true-negative samples
for the dataflow checks described by `sast-config`. Use them to verify that a
custom Semgrep rule or CodeQL query detects vulnerable flows without flagging
validated wrappers or parameterized query builders.

| Fixture | Expected Result | Flow Class | Evidence to Record |
|---------|-----------------|------------|--------------------|
| `vulnerable/command-injection-taint.py` | True positive | Flask request argument reaches `subprocess.run(..., shell=True)` | Rule/query id and finding output |
| `benign/validated-command-wrapper.py` | True negative | Flask request argument is decimal-validated and passed as an argument array | Rule/query id and no-finding output |
| `vulnerable/express-raw-sql-flow.js` | True positive | Express query parameter reaches raw SQL construction | Rule/query id and finding output |
| `benign/express-query-builder.js` | True negative | Express query parameter flows through parser plus query builder API | Rule/query id and no-finding output |

When a review accepts a sanitizer or wrapper as safe, cite the matching benign
fixture path and the scan output that stayed quiet. When a rule claims
source-to-sink coverage, cite the matching vulnerable fixture path and the
finding output that proves the flow is detected.
