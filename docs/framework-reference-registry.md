# Framework Reference Registry

The framework registry in [`data/frameworks.yaml`](../data/frameworks.yaml)
records the authoritative references SecuritySkills uses when skills cite
external security frameworks, standards, scoring systems, and control catalogs.

Every registry entry includes:

- `id`: canonical registry identifier.
- `family`: framework family such as `OWASP`, `NIST`, `MITRE`, `CIS`, `CVSS`,
  `SSVC`, `EPSS`, `SLSA`, `CycloneDX`, or `SPDX`.
- `name`: human-readable framework name.
- `version`: reviewed version or stable source state.
- `url`: authoritative HTTPS source.
- `date_reviewed`: date the registry entry was checked.
- `owner`: repo domain responsible for keeping the entry current.
- `aliases`: framework identifiers used in skill frontmatter or `index.yaml`.

The registry is intentionally separate from individual skill frontmatter. Skills
should continue to cite the most specific framework identifiers they use, while
the registry provides provenance, ownership, and review metadata for those
identifiers.

Validate the registry locally with:

```bash
ruby scripts/validate_framework_registry.rb
```

Report references whose `date_reviewed` value is older than the review policy
window with:

```bash
ruby scripts/validate_framework_registry.rb --stale --max-age-days 365
```

The scheduled `Validate framework registry` workflow runs this stale-reference
report weekly. Owners should refresh stale entries by confirming the source URL,
updating `version` when the upstream framework has changed, and setting a new
`date_reviewed`.
