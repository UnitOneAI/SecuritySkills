# Go Private Module Proxy and Checksum Edge Cases

These fixtures verify that dependency-scanning captures Go module proxy and checksum database evidence before judging private-module disclosure or dependency-confusion risk.

```yaml
case_id: GO-PRIVATE-01
title: Scoped private module policy is controlled
go_mod:
  module: github.com/example/service
  requires:
    - corp.example.com/platform/auth v1.2.3
go_env:
  GOPROXY: "https://proxy.corp.example.com,https://proxy.golang.org,direct"
  GOPRIVATE: "*.corp.example.com,github.com/example/private"
  GONOPROXY: ""
  GONOSUMDB: "*.corp.example.com,github.com/example/private"
  GOSUMDB: sum.golang.org
ci_go_env_captured: true
expected_classification:
  status: Benign / controlled
  reason: "Private prefixes are scoped out of public proxy/checksum behavior while public modules retain checksum verification."
```

```yaml
case_id: GO-PRIVATE-02
title: Missing GOPRIVATE leaks private module path to public proxy and sumdb
go_mod:
  module: corp.example.com/secret/payments-api
  requires:
    - corp.example.com/secret/payments v0.4.0
go_env:
  GOPROXY: "https://proxy.golang.org,direct"
  GOPRIVATE: ""
  GONOPROXY: ""
  GONOSUMDB: ""
  GOSUMDB: sum.golang.org
expected_classification:
  status: Private path disclosure
  severity: High
  reason: "Private module coordinates can be queried against public proxy and checksum database."
```

```yaml
case_id: GO-PRIVATE-03
title: Private proxy first still leaks on fallback without GOPRIVATE
go_mod:
  module: github.com/example/service
  requires:
    - corp.example.com/platform/billing v2.1.0
go_env:
  GOPROXY: "https://proxy.corp.example.com,https://proxy.golang.org,direct"
  GOPRIVATE: ""
  GONOPROXY: ""
  GONOSUMDB: "corp.example.com"
private_proxy_behavior:
  returns_404_for_missing_private_modules: true
expected_classification:
  status: Fallback leak risk
  severity: Medium
  reason: "Public fallback can receive private coordinates when private proxy returns 404/410."
```

```yaml
case_id: GO-PRIVATE-04
title: GOSUMDB disabled globally avoids disclosure but weakens public dependency integrity
go_mod:
  module: corp.example.com/service
  requires:
    - corp.example.com/platform/auth v1.2.3
    - github.com/gin-gonic/gin v1.10.0
go_env:
  GOPROXY: "https://proxy.corp.example.com,direct"
  GOPRIVATE: "corp.example.com"
  GONOSUMDB: "corp.example.com"
  GOSUMDB: "off"
internal_checksum_mirror: missing
expected_classification:
  status: Overbroad checksum disablement
  severity: Medium
  reason: "Public module checksum transparency is disabled globally without an internal mirror policy."
```

```yaml
case_id: GO-PRIVATE-05
title: GONOPROXY intentionally lets private proxy serve private modules while GONOSUMDB protects checksum privacy
go_mod:
  module: github.com/example/service
  requires:
    - github.com/example/private/auth v1.0.0
go_env:
  GOPROXY: "https://proxy.corp.example.com,https://proxy.golang.org,direct"
  GOPRIVATE: "github.com/example/private"
  GONOPROXY: "none"
  GONOSUMDB: "github.com/example/private"
  GOSUMDB: sum.golang.org
private_proxy_policy:
  serves_private_modules: true
  serves_public_cache: true
expected_classification:
  status: Benign / controlled
  reason: "Fine-grained settings intentionally use private proxy while excluding private modules from public checksum database."
```

```yaml
case_id: GO-PRIVATE-06
title: Developer go env is safe but CI evidence is missing
go_mod:
  module: github.com/example/service
  requires:
    - corp.example.com/platform/auth v1.2.3
developer_go_env:
  GOPRIVATE: "corp.example.com"
  GONOSUMDB: "corp.example.com"
ci_go_env_captured: false
expected_classification:
  status: Not evaluable
  reason: "Build/CI environment may differ from developer workstation and must be captured."
```

```yaml
case_id: GO-PRIVATE-07
title: GOINSECURE is not a privacy control
go_mod:
  module: corp.example.com/service
  requires:
    - corp.example.com/insecure/legacy v0.9.0
go_env:
  GOPROXY: "https://proxy.golang.org,direct"
  GOPRIVATE: ""
  GONOPROXY: ""
  GONOSUMDB: ""
  GOSUMDB: sum.golang.org
  GOINSECURE: "corp.example.com/insecure/*"
expected_classification:
  status: Private path disclosure
  severity: High
  reason: "GOINSECURE affects transport verification only; it does not prevent public proxy or checksum disclosure."
```
