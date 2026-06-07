# Vulnerable: mutable image tag with audit-only verification

This fixture should be flagged by the container-security skill because the
production workload uses a mutable tag, signature verification is audit-only,
and the exception can be self-attested by workload annotations.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payments-api
  template:
    metadata:
      labels:
        app: payments-api
      annotations:
        security.example.com/image-verification-exception: "temporary"
    spec:
      containers:
        - name: api
          image: registry.example.com/payments/api:latest
          imagePullPolicy: Always
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-production-images
spec:
  validationFailureAction: Audit
  rules:
    - name: verify-payments-images
      match:
        any:
          - resources:
              namespaces:
                - production
      verifyImages:
        - imageReferences:
            - "registry.example.com/payments/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
```

Expected findings:

- High: production image is tag-only (`:latest`) and not pinned by digest.
- Medium: signature policy is `Audit`, not enforce/deny mode.
- High: keyless attestor lacks a constrained `subject`.
- Medium: exception is declared by workload annotation without owner, ticket,
  expiration, or external approval evidence.
