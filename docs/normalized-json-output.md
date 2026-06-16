# Normalized JSON Output Contract

SecuritySkills can emit machine-readable findings as a normalized JSON envelope
that validates against [`schemas/finding.schema.json`](../schemas/finding.schema.json).
This contract is independent of SARIF. Downstream systems may map it to SARIF,
ticketing systems, GRC platforms, dashboards, or vulnerability stores without
changing individual skill output rules.
See [`docs/sarif-output.md`](sarif-output.md) for the repo-level SARIF 2.1.0
export mapping.

## Envelope

Every JSON response uses this top-level shape:

```json
{
  "schema_version": "1.0.0",
  "run": {
    "id": "run-2026-06-16T12:00:00Z",
    "timestamp": "2026-06-16T12:00:00Z",
    "tool": "codex",
    "target": "github.com/example/service",
    "source_ref": "commit-or-build-id"
  },
  "skill": {
    "name": "secure-code-review",
    "version": "1.0.0",
    "path": "skills/appsec/secure-code-review/SKILL.md",
    "frameworks": ["OWASP-ASVS-4.0.3", "CWE"]
  },
  "findings": []
}
```

- `schema_version` is fixed at `1.0.0` until a breaking contract change is
  required.
- `run.id` is the deduplication boundary for one execution. Use an orchestrator
  ID, CI job ID, or generated run ID.
- `run.timestamp` should be an ISO 8601 timestamp.
- `run.target` identifies the reviewed repository, project, service, artifact,
  environment, or evidence package.
- `skill.name`, `skill.version`, and `skill.frameworks` come from the skill's
  `SKILL.md` frontmatter.

## Findings

Each finding must include:

- `id`: stable finding ID within the run.
- `title`: concise finding title.
- `severity`: one of `info`, `low`, `medium`, `high`, or `critical`.
- `status`: one of `open`, `mitigated`, `accepted_risk`, or `false_positive`.
- `evidence`: one or more concrete evidence entries.
- `remediations`: one or more remediation recommendations, each with a test
  strategy.

Each finding must include at least one framework/CWE mapping:

- `cwe`: array of CWE IDs such as `CWE-89`, when applicable.
- `framework_refs`: array of framework/control references from the skill's
  declared frameworks.

Optional fields such as `fingerprint`, `description`, and `references` support
enterprise deduplication, analyst context, and external advisory linking.

## Evidence

Evidence entries must identify where the issue was observed and summarize the
observation. Locations may be source paths, line ranges, cloud resource IDs, log
sources, policy paths, scanner result identifiers, or evidence package records.

Use `snippet` only for the minimal redacted text needed to prove the finding.
Set `redacted: true` when secrets, tokens, personal data, internal hostnames, or
other sensitive values were removed.

## Remediation And Tests

Each remediation item must include:

- `guidance`: concrete remediation steps or patch guidance.
- `confidence`: `low`, `medium`, or `high`.
- `blast_radius`: expected affected files, systems, users, integrations, data,
  or workflows.
- `behavior_change_risk`: `low`, `medium`, or `high`.
- `test_strategy`: validation that proves the issue is fixed.

`test_strategy` must include a `summary` and at least one of
`recommended_tests` or `generated_tests`. See
[`docs/remediation-output.md`](remediation-output.md) for remediation-specific
field guidance.

## Minimal Example

```json
{
  "schema_version": "1.0.0",
  "run": {
    "id": "run-001",
    "timestamp": "2026-06-16T12:00:00Z",
    "tool": "codex",
    "target": "payments-api",
    "source_ref": "abc1234"
  },
  "skill": {
    "name": "api-security",
    "version": "1.0.0",
    "path": "skills/appsec/api-security/SKILL.md",
    "frameworks": ["OWASP-API-Top-10-2023", "CWE"]
  },
  "findings": [
    {
      "id": "API-SEC-001",
      "fingerprint": "api-security:users-delete:missing-admin-auth",
      "title": "Administrative endpoint lacks authorization check",
      "description": "The delete-user route accepts authenticated requests without verifying administrative privileges.",
      "severity": "high",
      "status": "open",
      "cwe": ["CWE-862"],
      "framework_refs": [
        {
          "framework": "OWASP-API-Top-10-2023",
          "control": "API5:2023",
          "name": "Broken Function Level Authorization"
        }
      ],
      "evidence": [
        {
          "location": "routes/users.js:42",
          "artifact_type": "source",
          "summary": "DELETE /users/:id checks authentication but not administrator role.",
          "snippet": "router.delete('/users/:id', requireAuth, deleteUser)",
          "redacted": false
        }
      ],
      "remediations": [
        {
          "guidance": "Require an administrator role check before invoking deleteUser.",
          "confidence": "high",
          "blast_radius": "User administration routes only.",
          "behavior_change_risk": "medium",
          "test_strategy": {
            "summary": "Proves non-admin users cannot delete accounts while admins still can.",
            "recommended_tests": [
              {
                "name": "Reject non-admin delete",
                "type": "integration",
                "purpose": "Confirms the vulnerable authorization bypass no longer succeeds.",
                "command": "npm test -- users-authz.test.js",
                "expected_result": "Non-admin DELETE /users/:id returns 403 and admin DELETE succeeds."
              }
            ]
          }
        }
      ]
    }
  ]
}
```
