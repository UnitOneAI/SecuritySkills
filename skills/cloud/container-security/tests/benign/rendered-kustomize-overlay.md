# Benign: Kustomize overlay supplies the final pod security context

This fixture calibrates `CS-RENDER-*` behavior. A reviewer who inspects only the
base manifest may report missing pod hardening, but the production overlay adds
the controls that appear in the rendered manifest.

## Base manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/example/api@sha256:1111111111111111111111111111111111111111111111111111111111111111
```

## Production overlay patch

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          securityContext:
            runAsUser: 65532
            runAsGroup: 65532
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

## Expected review result

- Do not mark the production workload as failing only from the base file.
- Require the rendered Kustomize output or an equivalent merged manifest.
- Record `Rendered Source: Kustomize overlay` and the overlay patch provenance.
