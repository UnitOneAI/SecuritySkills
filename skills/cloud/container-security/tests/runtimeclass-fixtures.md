# RuntimeClass Evidence Fixtures

Use these fixtures to verify that the container-security skill distinguishes verified sandboxed-runtime evidence from default-runtime or unverifiable claims.

## Benign: High-Risk Workload With Verified RuntimeClass

Expected result: pass the sandboxed runtime evidence gate while still evaluating ordinary Pod Security controls.

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sandbox-for-build-jobs
spec:
  validationFailureAction: Enforce
  rules:
    - name: isolated-builds-use-gvisor
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - isolated-builds
      validate:
        message: high-risk build jobs must use the gvisor runtime class
        pattern:
          spec:
            runtimeClassName: gvisor
---
apiVersion: batch/v1
kind: Job
metadata:
  name: user-submitted-code
  namespace: isolated-builds
spec:
  template:
    spec:
      runtimeClassName: gvisor
      automountServiceAccountToken: false
      containers:
        - name: executor
          image: ghcr.io/example/code-runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            seccompProfile:
              type: RuntimeDefault
      restartPolicy: Never
```

## Vulnerable: High-Risk Workload Without Sandboxed Runtime Evidence

Expected result: flag a sandboxed runtime evidence gap for a user-code executor. The pod may satisfy several Restricted controls, but high-risk execution still lacks verified runtime isolation.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: user-submitted-code
  namespace: isolated-builds
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: executor
          image: ghcr.io/example/code-runner:1.0
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            seccompProfile:
              type: RuntimeDefault
      restartPolicy: Never
```

## Not Evaluable: RuntimeClass Name Without Handler Evidence

Expected result: mark RuntimeClass evidence as Not Evaluable. The workload references `runtimeClassName: kata`, but the fixture lacks the matching RuntimeClass object, handler, node/runtime support, and admission evidence.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandboxed-worker
  namespace: isolated-builds
spec:
  template:
    spec:
      runtimeClassName: kata
      containers:
        - name: worker
          image: ghcr.io/example/worker@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
```

## Still Vulnerable: Sandboxed Runtime Does Not Waive Privileged Pod Settings

Expected result: flag privileged mode and host namespace findings even though a sandboxed runtime is referenced.

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged-plugin-runner
  namespace: isolated-builds
spec:
  template:
    spec:
      runtimeClassName: kata
      hostPID: true
      containers:
        - name: runner
          image: ghcr.io/example/plugin-runner@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
```
