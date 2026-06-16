# Tracker Handoff Format

SecuritySkills can emit tracker-ready work items for DefectDojo, Jira, Linear,
or equivalent issue trackers. The handoff format is an export view of the
normalized finding envelope documented in
[`docs/normalized-json-output.md`](normalized-json-output.md). It does not
replace normalized findings, perform live API calls, or require credentials.

The JSON shape validates against
[`schemas/tracker-handoff.schema.json`](../schemas/tracker-handoff.schema.json).

## Envelope

Every tracker handoff uses this top-level shape:

```json
{
  "schema_version": "1.0.0",
  "source": {
    "normalized_schema_version": "1.0.0",
    "run_id": "run-001",
    "generated_at": "2026-06-16T12:00:00Z",
    "target": "payments-api",
    "source_ref": "abc1234",
    "skill_name": "api-security",
    "skill_version": "1.0.0"
  },
  "work_items": []
}
```

- `schema_version` is fixed at `1.0.0` until a breaking handoff change is
  required.
- `source` identifies the normalized finding run that produced the handoff.
- `work_items` contains one tracker-ready item per normalized finding, unless a
  downstream workflow intentionally groups findings before export.

## Required Work Item Fields

Each work item must include:

- `title`: concise issue title suitable for a tracker summary.
- `severity`: one of `info`, `low`, `medium`, `high`, or `critical`.
- `evidence`: one or more concrete evidence entries with `location` and
  `summary`.
- `owner`: responsible person, team, service, or queue.
- `sla`: due date or timestamp plus the SLA policy or rationale.
- `remediation`: concrete guidance and validation summary.
- `tracker_fields`: explicit DefectDojo, Jira, and Linear import hints.

The handoff should preserve `source_finding_id` and, when available,
`source_finding_fingerprint` so importers can deduplicate work items without
depending on mutable titles.

## Mapping From Normalized Findings

| Normalized field | Tracker handoff field |
|---|---|
| `run.id`, `run.target`, `run.source_ref` | `source.run_id`, `source.target`, `source.source_ref` |
| `skill.name`, `skill.version` | `source.skill_name`, `source.skill_version` |
| `finding.id` | `work_items[].source_finding_id` |
| `finding.fingerprint` | `work_items[].source_finding_fingerprint` and `tracker_fields.defectdojo.unique_id_from_tool` |
| `finding.title` | `work_items[].title` |
| `finding.description` | `work_items[].description` and tracker description bodies |
| `finding.severity` | `work_items[].severity` and tracker priority/severity fields |
| `finding.evidence` | `work_items[].evidence` and tracker description bodies |
| `finding.references`, `finding.cwe`, `finding.framework_refs` | `work_items[].references`, labels, and tracker description bodies |
| `finding.remediations[0].guidance` | `work_items[].remediation.guidance` |
| `finding.remediations[0].test_strategy.summary` | `work_items[].remediation.validation` |

Owner and SLA are not present in the normalized finding contract. A handoff
producer must add them from routing rules, service ownership metadata, severity
policy, or an orchestrator-supplied assignment map before a work item is
considered tracker-ready.

## Severity And Priority

Use the normalized `severity` value as the canonical severity. Tracker-specific
fields may require translation:

| Normalized severity | DefectDojo severity | Jira priority | Linear priority |
|---|---|---|---|
| `critical` | `Critical` | `Highest` | `1` |
| `high` | `High` | `High` | `2` |
| `medium` | `Medium` | `Medium` | `3` |
| `low` | `Low` | `Low` | `4` |
| `info` | `Info` | `Lowest` | `0` |

Keep the original normalized severity in `work_items[].severity` even when a
tracker has fewer or differently named priority levels.

## Tracker Field Mappings

### DefectDojo

Map a work item to DefectDojo finding import fields:

| Handoff field | DefectDojo field |
|---|---|
| `title` | `title` |
| `severity` | `severity` |
| `description` plus evidence | `description` |
| `remediation.guidance` | `mitigation` |
| `source_finding_fingerprint` or `source_finding_id` | `unique_id_from_tool` |
| `source.target` or affected asset | `component_name` |
| CWE reference, when present | `cwe` |
| `references` | `references` |
| `labels` | `tags` |
| `sla.due_at` | `due_date` |

### Jira

Map a work item to Jira issue import fields:

| Handoff field | Jira field |
|---|---|
| `title` | `summary` |
| `description`, evidence, remediation, validation | `description` |
| Handoff policy | `issue_type`, usually `Bug`, `Task`, or `Security Finding` |
| `severity` | `priority` |
| `owner.id` | `assignee` |
| `sla.due_at` | `due_date` |
| `labels` | `labels` |
| Security classification policy | `security_level` |

### Linear

Map a work item to Linear issue fields:

| Handoff field | Linear field |
|---|---|
| `title` | `title` |
| `description`, evidence, remediation, validation | `description` |
| `severity` | `priority` |
| `owner.id` | `assignee_id` |
| Owner routing | `team_key` |
| `sla.due_at` | `due_date` |
| `labels` | `label_names` |
| Handoff workflow policy | `state_name` |

## Description Body

Tracker descriptions should be complete enough for an assignee to act without
opening the raw scanner output. Include:

- finding context and severity;
- concrete evidence locations and redacted snippets;
- remediation guidance;
- validation or test strategy;
- SLA due date and owner;
- CWE, framework, and external references when available.

Do not include secrets, tokens, personal data, or unredacted internal-only
values. Preserve `redacted: true` when evidence was sanitized.

## Minimal Example

```json
{
  "schema_version": "1.0.0",
  "source": {
    "normalized_schema_version": "1.0.0",
    "run_id": "run-001",
    "generated_at": "2026-06-16T12:00:00Z",
    "target": "payments-api",
    "source_ref": "abc1234",
    "skill_name": "api-security",
    "skill_version": "1.0.0"
  },
  "work_items": [
    {
      "id": "TRACKER-001",
      "source_finding_id": "API-SEC-001",
      "source_finding_fingerprint": "api-security:users-delete:missing-admin-auth",
      "title": "Administrative endpoint lacks authorization check",
      "severity": "high",
      "status": "ready",
      "description": "The delete-user route accepts authenticated requests without verifying administrative privileges.",
      "evidence": [
        {
          "location": "routes/users.js:42",
          "artifact_type": "source",
          "summary": "DELETE /users/:id checks authentication but not administrator role.",
          "snippet": "router.delete('/users/:id', requireAuth, deleteUser)",
          "redacted": false
        }
      ],
      "owner": {
        "type": "team",
        "id": "payments-platform",
        "display_name": "Payments Platform"
      },
      "sla": {
        "due_at": "2026-06-30",
        "policy": "High severity application security findings remediate within 14 days."
      },
      "remediation": {
        "guidance": "Require an administrator role check before invoking deleteUser.",
        "validation": "Run integration tests proving non-admin delete requests return 403 and admin delete requests still succeed.",
        "confidence": "high",
        "blast_radius": "User administration routes only.",
        "behavior_change_risk": "medium"
      },
      "labels": ["security", "api-security", "CWE-862"],
      "references": [
        {
          "type": "cwe",
          "id": "CWE-862",
          "url": "https://cwe.mitre.org/data/definitions/862.html"
        }
      ],
      "tracker_fields": {
        "defectdojo": {
          "title": "Administrative endpoint lacks authorization check",
          "severity": "High",
          "description": "The delete-user route accepts authenticated requests without verifying administrative privileges. Evidence: routes/users.js:42.",
          "mitigation": "Require an administrator role check before invoking deleteUser.",
          "unique_id_from_tool": "api-security:users-delete:missing-admin-auth",
          "component_name": "payments-api",
          "cwe": "CWE-862",
          "references": "https://cwe.mitre.org/data/definitions/862.html",
          "tags": ["security", "api-security", "CWE-862"],
          "due_date": "2026-06-30"
        },
        "jira": {
          "summary": "Administrative endpoint lacks authorization check",
          "description": "Severity: high\n\nEvidence:\n- routes/users.js:42: DELETE /users/:id checks authentication but not administrator role.\n\nRemediation: Require an administrator role check before invoking deleteUser.\n\nValidation: Run integration tests proving non-admin delete requests return 403 and admin delete requests still succeed.",
          "issue_type": "Security Finding",
          "priority": "High",
          "assignee": "payments-platform",
          "due_date": "2026-06-30",
          "labels": ["security", "api-security", "CWE-862"],
          "security_level": "Security"
        },
        "linear": {
          "title": "Administrative endpoint lacks authorization check",
          "description": "Severity: high\n\nEvidence:\n- routes/users.js:42: DELETE /users/:id checks authentication but not administrator role.\n\nRemediation: Require an administrator role check before invoking deleteUser.\n\nValidation: Run integration tests proving non-admin delete requests return 403 and admin delete requests still succeed.",
          "priority": 2,
          "assignee_id": "payments-platform",
          "team_key": "PAY",
          "due_date": "2026-06-30",
          "label_names": ["security", "api-security", "CWE-862"],
          "state_name": "Todo"
        }
      }
    }
  ]
}
```
