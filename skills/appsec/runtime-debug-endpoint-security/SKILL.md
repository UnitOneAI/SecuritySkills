# Runtime Debug Endpoint Security

## Overview

This skill performs a structured security review of runtime debug, diagnostic, and internal monitoring endpoints across web backends, cloud infrastructure, and internal tooling. It covers Flask debug mode, Django debug panel, Spring Boot Actuator, Kubernetes API servers, Prometheus metrics endpoints, Swagger/OpenAPI UIs, and custom diagnostic endpoints that may expose sensitive internal state, data, or operational capabilities.

Runtime debug endpoints are a frequent source of production information disclosure, privilege escalation, and supply chain compromise. They often bypass production security controls including authentication, rate limiting, and network segmentation.

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when:

- **Debug panels enabled in production** — Flask `debug=True`, Django `DEBUG=True`, or equivalent in deployed environments
- **Internal endpoints exposed externally** — Prometheus, Grafana, Swagger UI, Kibana, Kibana, or monitoring dashboards accessible without authentication
- **Spring Boot Actuator / management endpoints** — `/actuator/*`, `/manage/*` endpoints with sensitive probes
- **Kubernetes API / dashboard** — unauthenticated or weakly-authenticated K8s API servers, dashboards, or proxy endpoints
- **Incident response tooling** — debug endpoints used for incident handling that may persist beyond the incident window
- **CI/CD and deployment pipelines** — Jenkins, GitLab CI, GitHub Actions runner interfaces exposed in production networks

## Context

Runtime diagnostic endpoints are designed for development and troubleshooting but frequently persist into production deployments. They often provide privileged access to internal state, data, configuration, and operational controls.

### Common Attack Surfaces

| Endpoint Type | Typical Path | Risk Level |
|--------------|--------------|------------|
| Flask Debug Console | `/debug/`, `/flask-debug/` | CRITICAL |
| Django Debug Panel | `/django-debug-toolbar/` | HIGH |
| Spring Actuator | `/actuator/env`, `/actuator/heapdump` | CRITICAL |
| Swagger UI | `/swagger-ui.html`, `/api-docs` | MEDIUM |
| Prometheus | `/metrics`, `/-/healthy` | MEDIUM |
| K8s API Server | `/api/v1/`, `/logs/` | CRITICAL |
| Grafana | `/grafana/`, `/grafana/api/` | HIGH |
| JMX/JConsole | `:8080/`, `:5000/` | CRITICAL |
| Node.js inspector | `:9229/` | HIGH |
| Python werkzeug debugger | `/console/` | CRITICAL |

### Prerequisites

- Access to application source code or deployment manifests
- Network access to target endpoints for validation
- Dockerfile, Kubernetes manifests, or Helm charts
- Application configuration files (`.env`, `application.yml`, `settings.py`)

## Process

### Step 1: Discovery — Identify Debug/Diagnostic Endpoints

Use Glob to locate all debug and diagnostic endpoint configurations.

**Patterns to search:**

```
# Framework-specific debug configurations
**/app.py
**/wsgi.py
**/main.py
**/settings.py
**/application.yml
**/application.properties
**/Dockerfile
**/docker-compose.yml
**/deployment.yaml
**/values.yaml
```

**Key indicators:**

- `app.run(debug=True)` — Flask debug enabled
- `DEBUG = True` — Django debug mode
- `spring.security.enabled=false` — Spring security disabled
- `/actuator/*` — Spring Boot actuator endpoints
- `prometheus.io/scrape: "true"` — Prometheus scrape annotations
- `swagger-ui.html` or `SwaggerConfig` — Swagger/OpenAPI UI enabled
- `flask-debugtoolbar` or `django-debug-toolbar` — Debug toolbars
- `kubernetes.io/ingress` with debug paths
- Port mappings exposing debugger ports (9229, 5005, 8787)

### Step 2: Authority Assessment — Who Can Access Debug Endpoints

**MUST** verify that each debug endpoint has explicit authentication and authorization controls.

**MUST NOT** allow unauthenticated access to any debug endpoint in production environments.

**Critical checks:**

1. **Authentication:** Is there a gateway, proxy, or middleware enforcing authentication?
   - Check ingress controllers, reverse proxies, API gateways
   - Look for `auth-service` or `oauth2-proxy` annotations
   - Verify token validation middleware is present

2. **Authorization:** Does access control follow least privilege?
   - Should debug access be restricted to specific roles/IPs?
   - Are service accounts properly scoped?
   - Is RBAC configured for diagnostic tools?

3. **Network Segmentation:** Are debug endpoints isolated from public access?
   - Check network policies, security groups, firewall rules
   - Verify internal-only CIDR restrictions
   - Look for VPN/mesh requirements

### Step 3: Data Exposure Analysis — What Information Is Revealed?

**MUST** catalog all sensitive data exposed by each debug endpoint.

**Information disclosure risks:**

| Data Type | Example | Severity |
|-----------|---------|----------|
| Environment Variables | `os.environ`, `/actuator/env` | CRITICAL |
| Source Code | Stack traces, `code.interact()` | HIGH |
| Credentials | DB passwords, API keys, tokens | CRITICAL |
| Internal State | Bean definitions, service registry | HIGH |
| Database Access | JPA console, SQL queries | CRITICAL |
| Filesystem | `/proc`, `file:///` access | CRITICAL |
| Remote Execution | `exec`, `/invoke`, shell access | CRITICAL |

### Step 4: Capability Assessment — What Operations Are Available?

**MUST** document all operational capabilities exposed through debug endpoints.

**High-risk operations:**

- `heapdump` — Memory dump with potential secrets
- `threaddump` — Thread state with potential data in variables
- `logfile` — Log files with potential PII/secrets
- `restart` / `shutdown` — Service disruption
- `refresh` / `reload` — Configuration reload with new secrets
- `trace` — Request/response details with potential sensitive data
- `mappings` — Application routing with internal paths
- `auditevents` — Audit logs with potential security metadata

### Step 5: Validation — Confirm Remediation

**Before (vulnerable):**
```python
# Flask app with debug enabled in production
app = Flask(__name__)
app.run(debug=True, host='0.0.0.0', port=5000)  # DEBUG + EXPOSED
```

**After (remediated):**
```python
# Production config: debug disabled, bind to localhost only
app = Flask(__name__)
if app.config.get('DEBUG_MODE', False):
    app.run(debug=True, host='127.0.0.1', port=5000)  # Local only
else:
    # Use production WSGI server
    from gunicorn.app.base import Application
    # ... configure gunicorn for production
```

**Before (vulnerable):**
```yaml
# Kubernetes: Actuator exposed without auth
apiVersion: v1
kind: Service
spec:
  selector:
    app: my-service
  ports:
  - port: 8080
    targetPort: 8080  # Exposes /actuator/env, /actuator/heapdump
```

**After (remediated):**
```yaml
# Kubernetes: Actuator internal only with network policy
apiVersion: v1
kind: Service
metadata:
  annotations:
    internal-only: "true"
spec:
  selector:
    app: my-service
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
spec:
  podSelector:
    matchLabels:
      app: my-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          internal: "true"
    ports:
    - port: 8080
```

### Step 6: Incident Response — Handle Debug Endpoints in IR

**MUST** document procedures for managing debug endpoints during incidents.

**Best practices:**

- Use feature flags or environment-specific configs to enable/disable debug
- Implement debug endpoint access logging for audit trails
- Define incident response procedures for exposed debug endpoints
- Conduct regular debug endpoint audits as part of production reviews
- Use network-level controls (iptables, security groups) as defense-in-depth

## Verification

| | |
|---|---|
| **Input** | Application with `/actuator/env` exposed publicly |
| **Expected output** | CRITICAL finding with specific remediation guidance |
| **Pass condition** | Finding includes specific endpoint, exposed data type, and remediation |
| **Fail condition** | No finding or generic advice without actionable steps |

Step-by-step confirmation the fix held:
1. Scan for debug endpoint configurations using Glob + Grep.
2. Confirm authentication/authorization controls on each endpoint.
3. Confirm no sensitive data (credentials, source code, internal state) is exposed.
4. Confirm network segmentation prevents public access to internal endpoints.
5. Verify incident response procedures cover debug endpoint exposure.

## Gotchas (self-improvement loop)

**False positives**
- **Pattern:** `debug: true` in `tests/` or `conftest.py` — **Why:** Test environments — **Suppress:** only flag if debug config leaks to production deployment manifests or `settings.py` used in prod
- **Pattern:** `/metrics` endpoint in Prometheus ServiceMonitor — **Why:** Internal monitoring — **Suppress:** flag only if metrics are externally accessible (check ingress/network policy)
- **Pattern:** `swagger-ui.html` behind authenticated gateway — **Why:** Intentional API documentation — **Suppress:** verify authentication is enforced before reaching the endpoint

**Precision traps**
- **Trap:** Disabling debug breaks deployment — **Mitigation:** Use environment-specific configs or feature flags, never disable entirely without alternatives
- **Trap:** Prometheus metrics required for monitoring — **Mitigation:** Keep metrics but restrict to internal network, add authentication, remove sensitive labels

**Do NOT flag:** Public health check endpoints (`/health`, `/ready`, `/live`) that only return status codes without sensitive data.

## References (progressive disclosure)

- [OWASP Top 10 2021 — A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021_Security_Misconfiguration/)
- [OWASP Top 10 2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021_Broken_Access_Control/)
- [Spring Boot Actuator Security](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security)
- [Flask Debug Mode Security](https://flask.palletsprojects.com/en/2.3.x/debug/)
- [Django Debug Mode](https://docs.djangoproject.com/en/5.0/ref/settings/#debug)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/)

## Submission checklist

- [ ] Directory is `skills/appsec/runtime-debug-endpoint-security/`; entrypoint is `SKILL.md`
- [ ] Frontmatter complete; `name` matches the directory
- [ ] Every framework ID is real and resolves
- [ ] At least one machine-matchable detection signal (regex patterns in §2)
- [ ] Rules are hard constraints (no "consider"/"may")
- [ ] Before/after remediation example present
- [ ] Falsifiable verification test defined (binary pass/fail)
- [ ] Gotchas: 3 false positives + 2 precision traps
- [ ] `SKILL.md` stays lean
- [ ] `injection-hardened: true` — reviewed against OWASP LLM01:2025
- [ ] Commit message: `feat(skill): runtime-debug-endpoint-security — reviews debug/diagnostic endpoints for production exposure`

*SecuritySkills Skill Template v2 — UnitOne.ai*
