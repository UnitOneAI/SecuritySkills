# SSTI Template Evidence Fixtures

These fixtures calibrate the supplemental CWE-1336 server-side template injection gate in `secure-code-review`.

```yaml
case: static_template_with_untrusted_data
language: python
framework: flask
engine: jinja2
code_pattern: render_template_static_name
source:
  untrusted_value: current_user.display_name
sink:
  function: render_template
  template_name: profile.html
  template_name_controlled_by_user: false
  template_source_controlled_by_user: false
  value_passed_as_data: true
guardrails:
  autoescape_enabled: true
  custom_helpers_exposed: false
expected_decision: Pass
expected_findings: []
```

```yaml
case: user_controlled_jinja_template_source
language: python
framework: flask
engine: jinja2
code_pattern: render_template_string_request_body
source:
  parameter: form.body
  trust: attacker_controlled
sink:
  function: render_template_string
  template_source_controlled_by_user: true
guardrails:
  sandbox: missing
  helper_allowlist: missing
expected_decision: Fail
expected_findings:
  - check: CWE-1336
    severity: Critical
    reason: Attacker-controlled request body is evaluated as server-side Jinja template source.
```

```yaml
case: dynamic_template_name_without_allowlist
language: javascript
framework: express
engine: pug
code_pattern: res_render_query_template
source:
  parameter: query.template
  trust: attacker_controlled
sink:
  function: res.render
  template_name_controlled_by_user: true
guardrails:
  template_name_allowlist: missing
  path_traversal_check: missing
expected_decision: Fail
expected_findings:
  - check: CWE-1336
    severity: High
    reason: User-controlled template name can select server-side templates without an allowlist.
```

```yaml
case: tenant_template_with_unsafe_helper
language: javascript
framework: express
engine: handlebars
source:
  template_author: tenant_admin
  template_storage: database
  template_compiled_server_side: true
sink:
  function: handlebars.compile
  tenant_template_source_controlled: true
helpers:
  exec:
    exposed: true
    behavior: child_process_exec_sync
guardrails:
  helper_allowlist: unsafe
  preview_isolation: missing
  audit_logging: present
expected_decision: Fail
expected_findings:
  - check: CWE-1336
    severity: Critical
    reason: Tenant-authored templates can invoke a helper that executes OS commands.
```

```yaml
case: admin_authored_templates_sandboxed_and_audited
language: ruby
framework: rails
engine: liquid
source:
  template_author: admin
  role_restriction: content_admin
sink:
  function: liquid_render
  template_source_controlled_by_admin: true
guardrails:
  sandbox: enabled
  helper_allowlist: safe_filters_only
  filesystem_loader: disabled
  audit_logging: present
  preview_isolation: enabled
  rollback_path: present
expected_decision: Pass
expected_findings: []
```

```yaml
case: unsafe_freemarker_globals
language: java
framework: spring
engine: freemarker
source:
  template_source: cms_editor
sink:
  function: template.process
  template_source_controlled_by_editor: true
globals:
  object_wrapper: unrestricted
  template_class_resolver: unrestricted
guardrails:
  sandbox: missing
  role_restriction: weak
expected_decision: Fail
expected_findings:
  - check: CWE-1336
    severity: High
    reason: User-editable templates run with unrestricted FreeMarker globals and no sandbox evidence.
```

```yaml
case: template_engine_visible_but_source_to_sink_unknown
language: php
framework: symfony
engine: twig
available_evidence:
  - twig_environment_initialization
  - template_directory
missing_artifacts:
  - route_handlers
  - template_name_source
  - template_source_editor_permissions
  - helper_filter_global_registration
  - sandbox_configuration
expected_decision: Not Evaluable
expected_findings:
  - check: CWE-1336
    severity: Medium
    reason: Template engine use is visible, but source-to-sink and sandbox/helper evidence is missing.
```
