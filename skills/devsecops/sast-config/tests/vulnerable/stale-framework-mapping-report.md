# Vulnerable Fixture: Stale SAST Framework Mapping

## SAST Configuration Assessment Report

### Scope

- Repository: example-service
- SAST tool(s): Semgrep
- Configuration files analyzed: `.semgrep.yml`
- Date: 2026-06-03
- Frameworks applied: OWASP ASVS 4.0.3, CWE Top 25

### Finding

- Control Reference: ASVS V6.3.1 / CWE-20
- Description: The report treats ASVS 4.0.3 and an unspecified CWE Top 25 list as the current baseline.
- Expected skill behavior: flag this as stale unless the report records an explicit legacy assessment scope.

