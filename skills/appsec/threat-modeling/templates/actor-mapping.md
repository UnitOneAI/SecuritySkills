# Actor-Component Mapping Template

## Threat Actor to Component Mapping

Combine threat actor profiles with the component-threat matrix to produce a three-dimensional mapping showing which actors target which components via which threats.

| Actor | Capability Used | Target Component | STRIDE Threat | Likelihood Modifier | Resulting Risk |
|-------|----------------|-----------------|---------------|-------------------|---------------|
| Nation-State APT | Supply chain implant | CI/CD Pipeline | Tampering | +1 (high sophistication) | Critical |
| Organized Cybercrime | Credential stuffing | Auth Service | Spoofing | +0 (standard capability) | High |
| Malicious Insider | Legitimate DB access | Database | Info Disclosure | +1 (internal access) | Critical |
| Hacktivist | DDoS toolkit | API Gateway | Denial of Service | +0 | High |
| Supply Chain | Compromised package | Application Runtime | Elev. of Privilege | +1 (trusted context) | Critical |

## Instructions

1. For each relevant actor from the threat actor profiles, identify their most likely target components.
2. Map the actor's capabilities to specific STRIDE threats on those components.
3. Apply a likelihood modifier: +1 if the actor has special access or sophistication that increases likelihood beyond the base rating, +0 otherwise.
4. Recalculate risk using the modified likelihood in the risk matrix.
5. Flag any component targeted by 3+ actor types as a high-value target requiring defense-in-depth.
