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

## Reproducible Semgrep Evidence

The sample rules in `semgrep-rules/dataflow-evidence.yml` are intentionally
small. They give reviewers a concrete way to prove that a SAST configuration
tracks source-to-sink flow without flagging the paired benign wrapper.

Expected checks:

```bash
semgrep --config tests/semgrep-rules/dataflow-evidence.yml tests/vulnerable
semgrep --config tests/semgrep-rules/dataflow-evidence.yml tests/benign
```

Record the rule id, command, and finding count for each run. The vulnerable
directory should produce findings for the matching rule family; the benign
directory should stay quiet unless the reviewed sanitizer model is too broad or
too weak.

When a review accepts a sanitizer or wrapper as safe, cite the matching benign
fixture path and the scan output that stayed quiet. When a rule claims
source-to-sink coverage, cite the matching vulnerable fixture path and the
finding output that proves the flow is detected.
