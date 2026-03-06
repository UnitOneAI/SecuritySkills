# Docker and Kubernetes CIS Benchmark Details

This file contains the detailed CIS Docker Benchmark v1.6.0, CIS Kubernetes Benchmark v1.9.0, and NIST SP 800-190 checklist items for the Container & Kubernetes Security Review skill. See [SKILL.md](SKILL.md) for the main skill definition, process overview, and output format.

---

## Dockerfile Security Review (CIS Docker Benchmark v1.6.0, Section 4)

Evaluate Dockerfiles against CIS Docker Benchmark Section 4 (Container Images and Build File) and NIST SP 800-190 image risk countermeasures.

### CIS 4.1 -- Ensure That a User for the Container Has Been Created

**Critical check -- running as root is the most common container security issue:**

```dockerfile
# BAD: No USER directive (runs as root)
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y nginx
CMD ["nginx", "-g", "daemon off;"]

# GOOD: Non-root user
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y nginx && \
    groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
CMD ["nginx", "-g", "daemon off;"]
```

**Grep pattern:** Search for `USER` directive. If absent, flag as failure.

### CIS 4.2 -- Ensure That Containers Use Only Trusted Base Images

Check the `FROM` directive for trusted, official, or organization-approved base images:

```dockerfile
# PREFERRED: Official images with specific tags
FROM python:3.12-slim-bookworm
FROM node:20-alpine3.18
FROM gcr.io/distroless/java21-debian12

# RISKY: Unverified third-party images
FROM someuser/someimage
FROM random-registry.io/unknown-image

# BAD: Using latest tag (mutable, unpredictable)
FROM python:latest
FROM ubuntu
```

### CIS 4.3 -- Ensure That Unnecessary Packages Are Not Installed in the Container

Check for minimal base image usage and unnecessary package installation:

```dockerfile
# GOOD: Slim/Alpine base
FROM python:3.12-slim
FROM node:20-alpine

# GOOD: Distroless
FROM gcr.io/distroless/static-debian12

# BAD: Full OS base with unnecessary tools
FROM ubuntu:22.04
RUN apt-get install -y curl wget vim telnet netcat  # Attack tools in production
```

### CIS 4.4 -- Ensure Images Are Scanned and Rebuilt to Include Security Patches

Look for image scanning integration in CI/CD or Dockerfiles:

```dockerfile
# Check for pinned package versions (facilitates patching)
RUN apt-get install -y nginx=1.24.0-1~jammy  # Version pinned
```

### CIS 4.6 -- Ensure That HEALTHCHECK Instructions Have Been Added to Container Images

```dockerfile
# GOOD: Health check defined
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# BAD: No HEALTHCHECK instruction
```

### CIS 4.7 -- Ensure update/patch Instructions Are Not Used Alone in the Dockerfile

```dockerfile
# BAD: Update without installing specific packages (cache-busting only, no security value)
RUN apt-get update

# GOOD: Update combined with install in single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    package1=version1 \
    && rm -rf /var/lib/apt/lists/*
```

### CIS 4.9 -- Ensure That COPY Is Used Instead of ADD

```dockerfile
# BAD: ADD with remote URL (downloads arbitrary content)
ADD https://example.com/app.tar.gz /app/

# BAD: ADD with local tar (auto-extracts, unexpected behavior)
ADD app.tar.gz /app/

# GOOD: Explicit COPY
COPY app.tar.gz /app/
RUN tar -xzf /app/app.tar.gz -C /app/ && rm /app/app.tar.gz
```

### CIS 4.10 -- Ensure Secrets Are Not Stored in Dockerfiles

**Critical check:**

```dockerfile
# BAD: Secrets in ENV
ENV API_KEY=sk-1234567890abcdef
ENV DATABASE_URL=postgres://user:password@host/db

# BAD: Secrets in ARG (visible in image history)
ARG AWS_SECRET_ACCESS_KEY

# BAD: Secrets copied into image
COPY .env /app/.env
COPY credentials.json /app/

# GOOD: Multi-stage build with secrets only in build stage
FROM golang:1.21 AS builder
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install

# GOOD: Runtime secrets from environment/vault
ENV API_KEY_FILE=/run/secrets/api_key
```

**Grep patterns for secrets in Dockerfiles:**

```
ENV.*KEY=
ENV.*SECRET=
ENV.*PASSWORD=
ENV.*TOKEN=
ARG.*KEY
ARG.*SECRET
ARG.*PASSWORD
COPY.*\.env
COPY.*credential
COPY.*secret
COPY.*\.pem
COPY.*\.key
```

### Additional Dockerfile Checks

#### .dockerignore Review

Verify `.dockerignore` excludes sensitive files:

```
# Required exclusions
.git
.env
*.pem
*.key
credentials*
secrets*
.aws
.ssh
node_modules
__pycache__
```

#### Multi-Stage Build Usage

Check for multi-stage builds to minimize attack surface:

```dockerfile
# GOOD: Multi-stage build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o /app/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

---

## Kubernetes Security Review -- Pod Security (CIS Kubernetes v1.9.0, Section 5)

Evaluate Kubernetes workload definitions against CIS Kubernetes Benchmark Section 5 (Policies) and Pod Security Standards.

### CIS 5.1 -- RBAC and Service Accounts

#### CIS 5.1.1 -- Ensure that the cluster-admin role is only used where required

**Grep patterns:**

```yaml
# BAD: Binding cluster-admin to non-admin users/SAs
kind: ClusterRoleBinding
roleRef:
  name: cluster-admin
subjects:
  - kind: ServiceAccount  # Should be limited to system components
```

#### CIS 5.1.2 -- Minimize access to secrets

Check for RBAC rules granting broad secret access:

```yaml
# BAD: Wildcard access to secrets
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["*"]          # FAIL: should be specific verbs

# BAD: Cluster-wide secret access
kind: ClusterRole        # Should be Role (namespaced) for secret access
```

#### CIS 5.1.3 -- Minimize wildcard use in Roles and ClusterRoles

```yaml
# BAD: Wildcard resource or verb
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

#### CIS 5.1.5 -- Ensure that default service accounts are not actively used

```yaml
# BAD: Using default service account (implicit)
spec:
  # No serviceAccountName specified = uses "default"

# GOOD: Explicit service account
spec:
  serviceAccountName: my-app-sa
  automountServiceAccountToken: false  # If not needed
```

#### CIS 5.1.6 -- Ensure that Service Account Tokens are only mounted where necessary

```yaml
# GOOD: Disable auto-mount when not needed
spec:
  automountServiceAccountToken: false
```

### CIS 5.2 -- Pod Security Standards

Evaluate workload configurations against Kubernetes Pod Security Standards. The three levels are:

| Level | Description | Use Case |
|-------|-------------|----------|
| **Privileged** | Unrestricted. No security restrictions applied. | System-level workloads only (CNI, storage drivers) |
| **Baseline** | Minimally restrictive. Prevents known privilege escalations. | Standard workloads |
| **Restricted** | Heavily restricted. Follows current hardening best practices. | Security-sensitive and untrusted workloads |

#### CIS 5.2.1 -- Ensure that the cluster has at least one active policy control mechanism installed

Check for Pod Security Admission labels on namespaces:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Or check for OPA/Gatekeeper or Kyverno policies.

#### CIS 5.2.2 -- Minimize the admission of privileged containers

**Critical check:**

```yaml
# BAD: Privileged container
spec:
  containers:
    - name: app
      securityContext:
        privileged: true  # CRITICAL FAIL
```

**Grep pattern:** `privileged: true`

#### CIS 5.2.3 -- Minimize the admission of containers wishing to share the host process ID namespace

```yaml
# BAD
spec:
  hostPID: true  # FAIL
```

#### CIS 5.2.4 -- Minimize the admission of containers wishing to share the host IPC namespace

```yaml
# BAD
spec:
  hostIPC: true  # FAIL
```

#### CIS 5.2.5 -- Minimize the admission of containers wishing to share the host network namespace

```yaml
# BAD (unless required for system components)
spec:
  hostNetwork: true  # FAIL for application workloads
```

#### CIS 5.2.6 -- Minimize the admission of containers with allowPrivilegeEscalation

```yaml
# REQUIRED for Restricted profile
spec:
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false  # Must be false
```

**Grep pattern:** Check for absence of `allowPrivilegeEscalation: false` on all containers.

#### CIS 5.2.7 -- Minimize the admission of root containers

```yaml
# REQUIRED for Restricted profile
spec:
  containers:
    - name: app
      securityContext:
        runAsNonRoot: true       # Must be true
        runAsUser: 1000          # Explicit non-root UID
```

#### CIS 5.2.8 -- Minimize the admission of containers with the NET_RAW capability

```yaml
# GOOD: Drop all capabilities
spec:
  containers:
    - name: app
      securityContext:
        capabilities:
          drop: ["ALL"]
```

#### CIS 5.2.9 -- Minimize the admission of containers with added capabilities

```yaml
# BAD: Adding dangerous capabilities
securityContext:
  capabilities:
    add: ["SYS_ADMIN"]   # CRITICAL
    add: ["NET_ADMIN"]   # HIGH
    add: ["SYS_PTRACE"]  # HIGH
```

#### CIS 5.2.10 -- Minimize the admission of containers with capabilities assigned

Verify all containers drop ALL capabilities and only add back what is strictly needed:

```yaml
# GOOD: Minimal capabilities
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed for ports < 1024
```

#### CIS 5.2.11 -- Minimize the admission of Windows HostProcess containers

Check for `windowsOptions.hostProcess: true`.

#### CIS 5.2.12 -- Minimize the admission of HostPath volumes

```yaml
# BAD: HostPath volume mounts
volumes:
  - name: host-vol
    hostPath:
      path: /var/run/docker.sock  # CRITICAL: Docker socket mount
      path: /                      # CRITICAL: Root filesystem mount
      path: /etc                   # HIGH: Host config access
```

**Grep pattern:** `hostPath:` in volumes section.

#### CIS 5.2.13 -- Minimize the admission of containers which use HostPorts

```yaml
# BAD: Using host ports
ports:
  - containerPort: 8080
    hostPort: 8080  # FAIL: binds directly to host
```

### CIS 5.3 -- Network Policies and CNI

#### CIS 5.3.1 -- Ensure that the CNI in use supports NetworkPolicies

Verify a CNI plugin that supports NetworkPolicies is deployed (Calico, Cilium, Weave Net).

#### CIS 5.3.2 -- Ensure that all Namespaces have NetworkPolicies defined

Check for NetworkPolicy resources in each namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**Critical check:** A default-deny NetworkPolicy should exist in every namespace.

### CIS 5.4 -- Secrets Management

#### CIS 5.4.1 -- Prefer using Secrets as files over Secrets as environment variables

```yaml
# LESS SECURE: Secret as env var (visible in pod spec, logs)
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-secret
        key: password

# MORE SECURE: Secret as file mount
volumeMounts:
  - name: secret-vol
    mountPath: /etc/secrets
    readOnly: true
volumes:
  - name: secret-vol
    secret:
      secretName: db-secret
```

#### CIS 5.4.2 -- Consider external secret storage

Check for external secrets integration:

```yaml
# External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
spec:
  secretStoreRef:
    name: vault-backend
  target:
    name: app-secrets
```

Look for Vault Agent, Sealed Secrets, or External Secrets Operator configurations.

#### Hardcoded Secrets in Manifests

**Critical check -- secrets in plain YAML:**

```yaml
# BAD: Base64-encoded secret in manifest (trivially decodable)
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  password: cGFzc3dvcmQxMjM=  # Just base64, NOT encryption
```

Check whether Secret manifests are committed to version control. They should be managed via sealed secrets, external secrets operators, or excluded from the repository.

**Grep patterns:**

```
kind: Secret
data:
  .*: [A-Za-z0-9+/=]{8,}
stringData:
  password:
  token:
  api_key:
```

---

## Kubernetes Security Review -- Control Plane (CIS Kubernetes v1.9.0, Sections 1-4)

These checks apply when control plane configuration files are available (self-managed clusters).

### CIS 1.1 -- Control Plane Node Configuration Files

#### CIS 1.1.1 through 1.1.21 -- API Server, Controller Manager, Scheduler, and etcd file permissions

Verify configuration file permissions are restrictive:

```
# Expected permissions for control plane files
/etc/kubernetes/manifests/kube-apiserver.yaml    -- 600 or 644, owned by root:root
/etc/kubernetes/manifests/kube-controller-manager.yaml -- 600 or 644
/etc/kubernetes/manifests/kube-scheduler.yaml    -- 600 or 644
/etc/kubernetes/manifests/etcd.yaml              -- 600 or 644
/etc/kubernetes/admin.conf                       -- 600, root:root
```

### CIS 1.2 -- API Server Configuration

#### CIS 1.2.1 -- Ensure that the --anonymous-auth argument is set to false

```yaml
# kube-apiserver manifest
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=false
```

#### CIS 1.2.5 -- Ensure that the --kubelet-certificate-authority argument is set as appropriate

#### CIS 1.2.6 -- Ensure that the --authorization-mode argument is not set to AlwaysAllow

```yaml
- --authorization-mode=Node,RBAC  # Must NOT contain AlwaysAllow
```

#### CIS 1.2.9 -- Ensure that the admission control plugin EventRateLimit is set

#### CIS 1.2.10 -- Ensure that the admission control plugin AlwaysPullImages is set

#### CIS 1.2.11 -- Ensure that the admission control plugin SecurityContextDeny or PodSecurity is set

#### CIS 1.2.14 -- Ensure that the admission control plugin ServiceAccount is set

#### CIS 1.2.16 -- Ensure that the --audit-log-path argument is set

```yaml
- --audit-log-path=/var/log/kubernetes/audit.log
- --audit-log-maxage=30
- --audit-log-maxbackup=10
- --audit-log-maxsize=100
```

#### CIS 1.2.18 -- Ensure that the --audit-log-maxage argument is set to 30 or as appropriate

#### CIS 1.2.22 -- Ensure that the --audit-policy-file argument is set

### CIS 2.1 -- etcd Security

#### CIS 2.1 -- Ensure that the --cert-file and --key-file arguments are set as appropriate

#### CIS 2.2 -- Ensure that the --client-cert-auth argument is set to true

#### CIS 2.3 -- Ensure that the --auto-tls argument is not set to true

#### CIS 2.4 -- Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate

#### CIS 2.5 -- Ensure that the --peer-client-cert-auth argument is set to true

#### CIS 2.6 -- Ensure that the --peer-auto-tls argument is not set to true

#### CIS 2.7 -- Ensure that a unique Certificate Authority is used for etcd

---

## Container Runtime Hardening (NIST SP 800-190)

Evaluate container runtime configurations against NIST SP 800-190 countermeasures.

### NIST 800-190: Image Countermeasures

| Countermeasure | What to Check |
|---------------|---------------|
| **CM-1:** Use minimal base images | Verify Alpine, Distroless, or slim variants in FROM |
| **CM-2:** Scan images for vulnerabilities | Check for Trivy, Grype, Snyk in CI pipeline |
| **CM-3:** Sign and verify images | Check for Cosign signatures, Notary, or admission webhooks |
| **CM-4:** Use immutable tags or digests | `image: nginx@sha256:...` preferred over `image: nginx:1.25` |
| **CM-5:** Remove unnecessary packages | No curl, wget, netcat, or shells in production images |

### NIST 800-190: Orchestrator Countermeasures

| Countermeasure | What to Check |
|---------------|---------------|
| **CM-6:** Use namespaces for isolation | Workloads separated by namespace, not all in `default` |
| **CM-7:** Apply resource quotas and limits | ResourceQuota and LimitRange per namespace |
| **CM-8:** Implement network segmentation | NetworkPolicy in every namespace |
| **CM-9:** Use Pod Security Standards | PSA labels on namespaces or equivalent policy engine |
| **CM-10:** Enable audit logging | Audit policy configured on API server |

### NIST 800-190: Container Countermeasures

| Countermeasure | What to Check |
|---------------|---------------|
| **CM-11:** Run as non-root | `runAsNonRoot: true`, `runAsUser: >0` |
| **CM-12:** Use read-only root filesystem | `readOnlyRootFilesystem: true` |
| **CM-13:** Drop all capabilities | `capabilities.drop: ["ALL"]` |
| **CM-14:** Set resource limits | CPU and memory limits set on all containers |
| **CM-15:** Use seccomp profiles | `seccompProfile.type: RuntimeDefault` or custom |

**Resource limits check:**

```yaml
# REQUIRED: Resource limits on all containers
resources:
  requests:
    memory: "128Mi"
    cpu: "250m"
  limits:
    memory: "256Mi"
    cpu: "500m"
```

**Read-only root filesystem:**

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

**Seccomp profile:**

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

---

## Comprehensive Security Context Evaluation

For each workload (Deployment, StatefulSet, DaemonSet, Job, CronJob), evaluate the complete security context against the Restricted Pod Security Standard.

**Restricted PSS Requirements Checklist:**

```yaml
# Complete Restricted-compliant security context
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1000
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          type: RuntimeDefault
      resources:
        limits:
          memory: "256Mi"
          cpu: "500m"
        requests:
          memory: "128Mi"
          cpu: "250m"
```

**Fields that must NOT be present for Restricted compliance:**

- `privileged: true`
- `hostPID: true`
- `hostIPC: true`
- `hostNetwork: true`
- `hostPath` volumes
- `hostPort` in container ports
- Capabilities beyond the allowed set (only `NET_BIND_SERVICE` is permitted)
- `procMount` other than `Default`
- `appArmorProfile` of `unconfined`
