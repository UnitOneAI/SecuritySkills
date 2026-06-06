# Read-Only Default Permissions Evidence

This fixture should not be reported as confirmed broad `GITHUB_TOKEN` write
access solely because workflow YAML lacks a top-level `permissions:` block.

| Evidence Area | Evidence | Expected Result |
| --- | --- | --- |
| Workflow YAML | No explicit `permissions:` block | Needs platform evidence |
| Repository setting | Workflow permissions set to `Read repository contents permission` | Not write-all |
| Fork policy | Fork pull requests require approval and do not receive secrets | Reduced PPE exposure |

Expected classification: `Not Evaluable from Config` until repository or
organization Actions settings are reviewed; if read-only defaults are evidenced,
do not report a confirmed write-permission finding.
