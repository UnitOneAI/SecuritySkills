# RuntimeClass and admission policy edge cases

These fixtures support `skills/cloud/container-security/SKILL.md` runtime and admission evidence guidance.

## Benign exception: constrained root init container

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: volume-permissions
          image: busybox:1.36@sha256:4be8f0d59d41a3a494f1c350f064a9f1c8b3b7595510e164e47f2c6d3fda25a2
          command: ["sh", "-c", "chown -R 65532:65532 /work"]
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: work
              mountPath: /work
      containers:
        - name: app
          image: ghcr.io/example/app@sha256:1111111111111111111111111111111111111111111111111111111111111111
          securityContext:
            runAsUser: 65532
            runAsGroup: 65532
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      volumes:
        - name: work
          emptyDir: {}
```

Expected handling: do not score as the same risk as a long-running root application container. Verify exception evidence and flag missing context under `CONT-INIT-01`.

Review evidence to request:

- Container role, command, duration, mounts, hostPath absence, dropped capabilities, seccomp, read-only root filesystem, and image digest pinning.
- Whether admission policy validates init containers as well as app containers.
- Whether the volume target is scoped to an `emptyDir` or similarly isolated volume.

## Vulnerable: runtimeClassName without RuntimeClass object evidence

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: untrusted-plugin-runner
spec:
  template:
    spec:
      runtimeClassName: gvisor
      containers:
        - name: runner
          image: ghcr.io/example/plugin-runner@sha256:2222222222222222222222222222222222222222222222222222222222222222
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
```

Expected finding when the matching object is not reviewed: `CONT-RUNTIME-01`.

Review evidence to request:

- Matching `RuntimeClass` object and handler/runtime implementation.
- Namespace or node eligibility for the sandbox runtime.
- Justification if a high-risk plugin runner uses the default runtime.

## Vulnerable: admission policy exists but is audit-only

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-runtime-default-seccomp
spec:
  validationFailureAction: Audit
  rules:
    - name: require-runtime-default
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        pattern:
          spec:
            securityContext:
              seccompProfile:
                type: RuntimeDefault
```

Expected finding: `CONT-ADMISSION-01`.

Review evidence to request:

- Whether the policy mode is `Enforce`, `Audit`, dry-run, or warn-only.
- Namespace and object selectors for the workload under review.
- Exception resources and excluded service accounts or namespaces.

## Vulnerable: CEL admission resources not discovered

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-non-root
spec:
  validations:
    - expression: "object.spec.securityContext.runAsNonRoot == true"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-non-root-binding
spec:
  policyName: require-non-root
  validationActions: ["Warn"]
```

Expected finding: `CONT-ADMISSION-05` or `CONT-ADMISSION-01` when the binding is warn-only.

Review evidence to request:

- `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding` resources.
- `MutatingAdmissionPolicy` and `MutatingAdmissionPolicyBinding` resources when mutation is expected.
- Binding validation actions, namespace selectors, and workload match evidence.

## Vulnerable: policy omits init or ephemeral containers

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPAllowPrivilegeEscalationContainer
metadata:
  name: deny-privilege-escalation
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    exemptImages: ["registry.local/debug:*"]
```

Expected finding: `CONT-ADMISSION-04` when coverage is not proven for init and ephemeral containers, and `CONT-ADMISSION-03` when exceptions are broad.

Review evidence to request:

- Constraint template logic proving app, init, and ephemeral containers are checked.
- Exception scope, owner, expiry, and review evidence.
- Workload labels and namespace selectors proving the policy matches the assessed pod.
