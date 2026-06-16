# SARIF Output Mapping

SecuritySkills may emit SARIF-compatible JSON for tools that ingest Static
Analysis Results Interchange Format (SARIF) 2.1.0. SARIF output is an export
view of the normalized finding envelope documented in
[`docs/normalized-json-output.md`](normalized-json-output.md); it does not
replace the normalized JSON contract or change the required finding fields.

## Top-Level Shape

Use SARIF version `2.1.0` with the standard schema URI:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SecuritySkills",
          "semanticVersion": "1.0.0",
          "rules": []
        }
      },
      "results": []
    }
  ]
}
```

Use one `run` per normalized envelope. `run.tool.driver.name` should identify
SecuritySkills or the executing agent. `run.tool.driver.semanticVersion` should
use the skill version when a single skill produced the run.

## Mapping

Map normalized fields to SARIF as follows:

| Normalized field | SARIF field |
|---|---|
| `run.id`, `run.timestamp`, `run.target`, `run.source_ref` | `runs[].properties.securityskills.run` |
| `skill.name`, `skill.version`, `skill.path`, `skill.frameworks` | `runs[].tool.driver.name`, `runs[].tool.driver.semanticVersion`, `runs[].properties.securityskills.skill` |
| `finding.id` | `results[].ruleId` and `results[].properties.securityskills.finding_id` |
| `finding.fingerprint` | `results[].partialFingerprints.securityskillsFingerprint` |
| `finding.title` | `tool.driver.rules[].shortDescription.text` |
| `finding.description` | `tool.driver.rules[].fullDescription.text` and `results[].message.text` |
| `finding.severity` | `results[].level` |
| `finding.status` | `results[].properties.securityskills.status` |
| `finding.cwe` | `tool.driver.rules[].relationships` when supported, and `properties.securityskills.cwe` |
| `finding.framework_refs` | `tool.driver.rules[].properties.securityskills.framework_refs` |
| `finding.evidence` | `results[].locations` plus `properties.securityskills.evidence` |
| `finding.references` | `tool.driver.rules[].helpUri` or `tool.driver.rules[].properties.securityskills.references` |
| `finding.remediations` | `tool.driver.rules[].help.text` and `properties.securityskills.remediations`, including each remediation's `test_strategy` |

## Severity

SARIF `level` has fewer values than the normalized contract. Use this mapping:

| Normalized severity | SARIF level |
|---|---|
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |
| `info` | `note` |

Keep the original severity in
`results[].properties.securityskills.severity` so downstream systems can
preserve the distinction between `critical` and `high`.

## Locations

For source, configuration, policy, or scan-result evidence with file locations,
populate `results[].locations[].physicalLocation`:

```json
{
  "physicalLocation": {
    "artifactLocation": {
      "uri": "routes/users.js"
    },
    "region": {
      "startLine": 42
    }
  },
  "message": {
    "text": "DELETE /users/:id checks authentication but not administrator role."
  }
}
```

If the normalized evidence location does not contain a parseable file path and
line number, still emit a SARIF result and store the original location under
`properties.securityskills.evidence`. For cloud resources, identities, network
assets, logs, or documents, use the best stable asset identifier as
`artifactLocation.uri` only when it is meaningful to the SARIF consumer.

## Rules

Create one `tool.driver.rules[]` entry per distinct `ruleId`. A rule should
include:

- `id`: the normalized `finding.id`, or a stable detector ID when multiple
  findings share the same detection rule.
- `shortDescription.text`: the finding title or detector title.
- `fullDescription.text`: the finding description.
- `help.text`: remediation guidance and test strategy summary.
- `properties.securityskills`: CWE IDs, framework references, normalized
  severity, and any remediation metadata that does not fit native SARIF fields.

Do not invent CWE, framework, or control identifiers for SARIF. Reuse only the
values already present in the normalized finding.

## Minimal Example

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "api-security",
          "semanticVersion": "1.0.0",
          "rules": [
            {
              "id": "API-SEC-001",
              "shortDescription": {
                "text": "Administrative endpoint lacks authorization check"
              },
              "fullDescription": {
                "text": "The delete-user route accepts authenticated requests without verifying administrative privileges."
              },
              "help": {
                "text": "Require an administrator role check before invoking deleteUser. Validate with integration tests for non-admin and admin delete flows."
              },
              "properties": {
                "securityskills": {
                  "severity": "high",
                  "cwe": ["CWE-862"],
                  "framework_refs": [
                    {
                      "framework": "OWASP-API-Top-10-2023",
                      "control": "API5:2023",
                      "name": "Broken Function Level Authorization"
                    }
                  ]
                }
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "API-SEC-001",
          "level": "error",
          "message": {
            "text": "Administrative endpoint lacks authorization check"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "routes/users.js"
                },
                "region": {
                  "startLine": 42
                }
              },
              "message": {
                "text": "DELETE /users/:id checks authentication but not administrator role."
              }
            }
          ],
          "partialFingerprints": {
            "securityskillsFingerprint": "api-security:users-delete:missing-admin-auth"
          },
          "properties": {
            "securityskills": {
              "finding_id": "API-SEC-001",
              "severity": "high",
              "status": "open",
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
                        "purpose": "Confirms the authorization bypass no longer succeeds.",
                        "command": "npm test -- users-authz.test.js",
                        "expected_result": "Non-admin DELETE returns 403 and admin DELETE succeeds."
                      }
                    ]
                  }
                }
              ]
            }
          }
        }
      ],
      "properties": {
        "securityskills": {
          "run": {
            "id": "run-001",
            "timestamp": "2026-06-16T12:00:00Z",
            "target": "payments-api",
            "source_ref": "abc1234"
          },
          "skill": {
            "name": "api-security",
            "version": "1.0.0",
            "path": "skills/appsec/api-security/SKILL.md",
            "frameworks": ["OWASP-API-Top-10-2023", "CWE"]
          }
        }
      }
    }
  ]
}
```
