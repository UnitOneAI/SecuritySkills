# Java Repository Source Edge Cases

These fixtures verify that dependency-scanning captures Gradle and Maven repository-source evidence before judging dependency-confusion or private-coordinate disclosure risk.

```yaml
case_id: JAVA-REPO-01
title: Gradle exclusiveContent constrains internal group to private repository
build_tool: Gradle
repositories:
  - type: mavenCentral
  - type: exclusiveContent
    repository: https://repo.example.internal/maven2
    filter:
      include_groups:
        - com.example.internal
dependencies:
  - com.example.internal:payments-client:1.4.0
expected_classification:
  status: Benign / controlled
  reason: "exclusiveContent prevents public repositories from being queried for the internal group."
```

```yaml
case_id: JAVA-REPO-02
title: Gradle public repository can see internal coordinates
build_tool: Gradle
repositories:
  - https://repo.maven.apache.org/maven2
  - https://repo.example.internal/maven2
filters: missing
dependencies:
  - com.example.internal:payments-client:1.4.0
expected_classification:
  status: Private coordinate leak
  severity: High
  reason: "No content filter or exclusiveContent prevents public repository lookup for private group."
```

```yaml
case_id: JAVA-REPO-03
title: Maven POM order cannot prove private groups avoid Central
build_tool: Maven
pom_repositories:
  - id: central
    url: https://repo.maven.apache.org/maven2
  - id: internal
    url: https://repo.example.internal/maven2
effective_settings:
  mirrors: missing
  active_profiles: missing
effective_pom: missing
dependencies:
  - com.example.internal:payments-client:1.4.0
expected_classification:
  status: Not evaluable
  reason: "Raw POM repository order is insufficient without effective settings, mirrors, and active profile evidence."
```

```yaml
case_id: JAVA-REPO-04
title: Gradle dependency repositories filtered but plugin repositories are not
build_tool: Gradle
dependency_repositories:
  exclusive_content:
    repository: https://repo.example.internal/maven2
    include_groups:
      - com.example.internal
plugin_management_repositories:
  - gradlePluginPortal
  - https://repo.example.internal/gradle-plugins
internal_plugins:
  - com.example.internal.release
expected_classification:
  status: Plugin repository leak risk
  severity: Medium
  reason: "Internal plugin IDs may resolve through the public plugin portal without pluginManagement filtering."
```

```yaml
case_id: JAVA-REPO-05
title: Repository manager routes public and private artifacts with allowlists
build_tool: Mixed
repository_manager:
  product: Nexus
  group_repository: https://repo.example.internal/maven-all
  routing_rules:
    internal_group_allowlist:
      - com.example.internal
    public_proxy_allowlist:
      - org.apache.*
      - com.fasterxml.jackson.*
    public_fallback_for_internal_groups: false
gradle_repositories:
  - https://repo.example.internal/maven-all
maven_effective_settings:
  mirrors:
    - mirrorOf: "*"
      url: https://repo.example.internal/maven-all
dependencies:
  - com.example.internal:payments-client:1.4.0
expected_classification:
  status: Benign / controlled
  reason: "Repository-manager routing and effective build settings prove internal groups cannot fall through to public repositories."
```

```yaml
case_id: JAVA-REPO-06
title: Maven effective settings mirror controls a risky-looking POM
build_tool: Maven
pom_repositories:
  - id: central
    url: https://repo.maven.apache.org/maven2
  - id: internal
    url: https://repo.example.internal/maven2
effective_settings:
  mirrors:
    - mirrorOf: "*"
      url: https://repo.example.internal/maven-all
repository_manager_policy:
  public_fallback_for_internal_groups: false
dependencies:
  - com.example.internal:payments-client:1.4.0
expected_classification:
  status: Benign / controlled
  reason: "Effective settings are stronger evidence than a raw POM and route all resolution through the internal manager."
```

```yaml
case_id: JAVA-REPO-07
title: Maven CI profile may add a public fallback repository
build_tool: Maven
pom_repositories:
  - id: internal
    url: https://repo.example.internal/maven2
profiles:
  ci-public-fallback:
    activation: property:ci
    repositories:
      - id: central
        url: https://repo.maven.apache.org/maven2
private_coordinates:
  - com.example.internal:auth-client
ci_evidence:
  active_profiles: missing
  effective_pom: missing
  effective_settings: missing
expected_classification:
  status: Not evaluable
  reason: "Active profile evidence is required before deciding whether CI adds public fallback for internal groups."
```
