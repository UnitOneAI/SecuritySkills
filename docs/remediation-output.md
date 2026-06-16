# Remediation Output Fields

SecuritySkills fix recommendations should be emitted as structured remediation
items under each finding. Every remediation item must include:

- `guidance`: concrete remediation steps or patch guidance.
- `confidence`: `low`, `medium`, or `high` confidence that the recommendation is correct for the observed evidence.
- `blast_radius`: the expected scope of systems, files, users, integrations, data, or workflows affected by the change.
- `behavior_change_risk`: `low`, `medium`, or `high` risk that the fix changes intended behavior.

`test_strategy` is optional in the normalized schema. Include it when the skill
can name a concrete validation approach, but keep detailed test strategy policy
in the dedicated test-strategy workstream.

The machine-readable contract lives in
[`schemas/finding.schema.json`](../schemas/finding.schema.json).
