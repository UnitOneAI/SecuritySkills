# CI/CD Examples

These examples wire SecuritySkills repository validation into common CI/CD
systems. They are intentionally small so maintainers can copy them into a
consumer repository and then add an agent-specific review step when needed.

Every hosted CI example runs:

```bash
ruby scripts/validate_skill_schema.rb
ruby scripts/validate_index.rb
ruby scripts/test_skill_fixtures.rb
```

Those checks validate skill frontmatter, role bundles, `index.yaml`, fixture
manifests, and expected evidence strings. Each pipeline also prepares
`artifacts/securityskills/` as the conventional location for normalized finding
JSON and SARIF output from an agent review step. Use
[`docs/normalized-json-output.md`](normalized-json-output.md) for the normalized
JSON envelope and [`docs/sarif-output.md`](sarif-output.md) for SARIF 2.1.0
mapping.

## GitHub Actions

Copy [`examples/ci/github-actions.yml`](../examples/ci/github-actions.yml) to
`.github/workflows/securityskills.yml`.

The workflow uses `ruby/setup-ruby`, validates the repository on pull requests
and pushes to `main`, and uploads any `artifacts/securityskills/*.json` or
`*.sarif` files that an added review step produces.

## GitLab CI

Copy [`examples/ci/gitlab-ci.yml`](../examples/ci/gitlab-ci.yml) to
`.gitlab-ci.yml`.

The job runs in the `ruby:3.2` container image, validates the repository, and
keeps optional normalized JSON and SARIF artifacts for 14 days.

## Azure DevOps

Copy [`examples/ci/azure-pipelines.yml`](../examples/ci/azure-pipelines.yml) to
`azure-pipelines.yml`.

The pipeline runs on `ubuntu-latest`, executes the repository validators, and
publishes `artifacts/securityskills/` as a build artifact even when validation
fails.

## Jenkins

Copy [`examples/ci/Jenkinsfile`](../examples/ci/Jenkinsfile) to `Jenkinsfile`.

The pipeline assumes Ruby is already installed on the Jenkins agent. If your
agent image does not include Ruby, add the installation step that matches your
Jenkins environment before the validation commands.

## pre-commit

Copy
[`examples/ci/pre-commit-config.yaml`](../examples/ci/pre-commit-config.yaml)
to `.pre-commit-config.yaml`, or merge the local hooks into an existing config.

Run the hooks locally with:

```bash
pre-commit run --all-files
```

The hooks use `language: system`, so Ruby must be available in the developer
environment.

## Local Agent Usage

Run [`examples/ci/local-agent.sh`](../examples/ci/local-agent.sh) from a clone
of this repository:

```bash
examples/ci/local-agent.sh path/to/target
```

The script validates the repository, creates `artifacts/securityskills/`, and
writes an agent prompt that asks for both:

- `artifacts/securityskills/securityskills-findings.json`
- `artifacts/securityskills/securityskills-findings.sarif`

Set `SKILL_PATH` to review with a specific skill:

```bash
SKILL_PATH=skills/devsecops/pipeline-security/SKILL.md examples/ci/local-agent.sh .
```

The script does not invoke a hosted model or require credentials. It prints a
copy-paste Codex command so teams can adapt it to Codex CLI, Claude Code,
Gemini CLI, Cursor, Kiro, or another local agent.

## Validating These Examples

Run the example validator after changing any files in `examples/ci/`:

```bash
ruby scripts/validate_ci_cd_examples.rb
```

The validator parses the YAML examples, checks that each platform includes the
three repository validation commands, confirms Jenkins archives optional
artifacts, and syntax-checks the local agent shell script.
