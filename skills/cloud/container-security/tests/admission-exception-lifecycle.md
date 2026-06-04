# Admission Exception Lifecycle Calibration

Use these samples to calibrate the `container-security` skill's admission-control
exception checks.

---

## Should Trigger: Permanent Privileged Namespace Exception

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production-debug
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
```

Expected finding:

- **Status:** Fail
- **Severity:** High
- **Reason:** The production namespace downgrades Pod Security Admission to
  privileged with no owner, ticket, expiry, review cadence, compensating
  controls, or cleanup evidence.

---

## Should Trigger: Broad Unsigned Image Policy Exception

```yaml
apiVersion: policies.kyverno.io/v1beta1
kind: PolicyException
metadata:
  name: unsigned-tools
  namespace: policy-exceptions
spec:
  policyRefs:
    - name: require-signed-images
      kind: ImageValidatingPolicy
  images:
    - "registry.example.com/tools/*:latest"
  matchConditions:
    - name: broad-production-tools
      expression: "object.metadata.namespace.startsWith('prod')"
```

Expected finding:

- **Status:** Fail
- **Severity:** High
- **Reason:** The exception bypasses all rules for all namespaces and a mutable
  image tag/prefix, with no owner, reason, approval, expiry, or digest binding.

---

## Should Not Trigger: Controlled IR Debug Exception

```yaml
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: ir-debug-hostaccess-20260605
  namespace: policy-exceptions
  annotations:
    security.example.com/owner: incident-commander
    security.example.com/ticket: INC-2026-0605
    security.example.com/reason: "4h privileged debug pod on tainted IR node"
    security.example.com/expires-at: "<incident-start + 4h RFC3339>"
    security.example.com/cleanup-required: "delete debug pod and exception after incident"
spec:
  exceptions:
    - policyName: restricted-pod-security
      ruleNames:
        - disallow-privileged
  match:
    any:
      - resources:
          namespaces:
            - incident-response
          kinds:
            - Pod
          names:
            - ir-debug-shell
          operations:
            - CREATE
```

Expected handling:

- **Status:** Controlled Exception
- **Reason:** The exception is narrow, time-bound, owned, ticketed, and has a
  cleanup requirement. Reviewers should still request audit/report evidence that
  the exception was used only for the named debug workload and removed after
  expiry.
