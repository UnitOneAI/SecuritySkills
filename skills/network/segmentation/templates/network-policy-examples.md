# Network Policy Examples

Extracted from the segmentation SKILL.md.

## Kubernetes NetworkPolicy -- Default Deny

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}        # applies to all pods in namespace
  policyTypes:
    - Ingress
    - Egress
```

## Calico GlobalNetworkPolicy -- Default Deny

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: all()
  types:
    - Ingress
    - Egress
```

## Best Practices

- Deploy default-deny NetworkPolicy in every production namespace
- Explicitly allow only required communication paths
- Use label selectors for fine-grained pod-to-pod policies
- Test policies in audit/log mode before enforcing
- Use GitOps for policy management
