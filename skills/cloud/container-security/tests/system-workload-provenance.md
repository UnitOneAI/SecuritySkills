# System Workload Exception and Image Provenance Fixture

Use this fixture to validate that container-security reviews distinguish platform workload exceptions from ordinary application violations without losing enforcement evidence.

## Benign With Evidence

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cilium-agent
  namespace: kube-system
  annotations:
    security.unitone.ai/exception-owner: platform-networking
    security.unitone.ai/change-ticket: CHG-2026-0604
    security.unitone.ai/reviewed: "2026-06-04"
spec:
  template:
    spec:
      hostNetwork: true
      serviceAccountName: cilium
      containers:
        - name: cilium-agent
          image: quay.io/cilium/cilium@sha256:abc123
          securityContext:
            capabilities:
              add: ["NET_ADMIN", "SYS_ADMIN"]
```

Required evidence:

- system workload role: CNI agent in `kube-system`
- scoped RBAC and namespace boundary documented
- image digest plus signature/attestor evidence recorded
- admission policy denies the same `hostNetwork` and capability set in application namespaces
- owner, change-control ticket, review date, and compensating controls recorded

## Vulnerable App Namespace

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-debug
  namespace: production
spec:
  ephemeralContainers:
    - name: debug
      image: busybox:latest
      securityContext:
        privileged: true
```

Expected finding:

- `ephemeralContainers` were included in the PSS matrix.
- `busybox:latest` is mutable and lacks digest/signature evidence.
- privileged debug container in an application namespace is High/Critical unless policy denies it.

## Incomplete Provenance

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: sign-images
spec:
  validationFailureAction: Audit
  rules:
    - name: require-cosign
      verifyImages:
        - imageReferences: ["ghcr.io/example/*"]
```

Expected finding: signing guidance is incomplete because policy is audit-only and no denial evidence proves unsigned images are rejected at admission time.
