# Vulnerable: CronJob renders a privileged pod template

This fixture calibrates `CS-WORKLOAD-*` behavior. The unsafe pod spec is nested
under `spec.jobTemplate.spec.template.spec`, so checks that only inspect
Deployment-style `spec.template.spec` paths miss it.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-export
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: default
          containers:
            - name: exporter
              image: ghcr.io/example/exporter:latest
              securityContext:
                privileged: true
                allowPrivilegeEscalation: true
                capabilities:
                  add: ["SYS_ADMIN"]
              volumeMounts:
                - name: docker-sock
                  mountPath: /var/run/docker.sock
          volumes:
            - name: docker-sock
              hostPath:
                path: /var/run/docker.sock
          restartPolicy: OnFailure
```

## Expected findings

- Critical: privileged CronJob pod template.
- Critical: Docker socket hostPath mount.
- High: default service account used by the CronJob-created pods.
- Evidence must include `Workload Kind: CronJob` and
  `Pod Spec Path: spec.jobTemplate.spec.template.spec`.
