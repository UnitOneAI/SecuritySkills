# Ephemeral Runner Group Evidence

This fixture should not be reported as blanket high severity merely because a
workflow uses `runs-on: self-hosted`.

| Evidence Area | Evidence | Expected Result |
| --- | --- | --- |
| Runner lifecycle | Just-in-time runner destroyed after one job | Lower persistence risk |
| Runner group | Scoped to one repository and protected environment | No shared trust boundary |
| Fork policy | Untrusted fork pull requests cannot target the runner group | No fork code on runner |
| Network | Egress allowlist and no production network reachability | Reduced lateral movement |
| Workspace | Fresh workspace per job with post-job cleanup attestation | No shared writable state |

Expected classification: pass or low residual risk when all evidence is present.
If runner inventory is unavailable, use `Not Evaluable from Config`.
