# Vulnerable: stale EO 14028 source citation

## Scenario

An SBOM compliance review cites EO 14028 through the current White House site:

```markdown
EO 14028 source: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
Source status: assumed current
```

## Expected Review Result

Treat the regulatory source as stale unless a reachable official archive or publication source is recorded.
For federal supply-chain and SBOM compliance references, reviewers should prefer a stable official source.
