## DNS Security Assessment Report

### Scope
- DNS infrastructure reviewed: public authoritative zones and recursive resolvers
- Configuration files analyzed: `named.conf`
- Date: 2026-06-03
- Frameworks applied: NIST SP 800-81 Rev 2, CIS Controls v8 (9.2)

### DNSSEC Status

| Zone | Signed | Algorithm | Key Sizes | DS in Parent | NSEC Version | Status |
|------|--------|-----------|-----------|--------------|-------------|--------|
| example.com | Yes | 8 | KSK:2048/ZSK:1024 | Yes | NSEC3 | Pass |

### Resolver Security

| Resolver | DNSSEC Validation | Encrypted Transport | RPZ/Filtering | Query Logging |
|----------|-------------------|--------------------|--------------|--------------|
| resolver-1 | Enabled | DoH | Yes | Yes |

### Finding Expected From Skill

- Severity: Medium
- Control Reference: NIST SP 800-81 Rev. 3 revision/source-date preflight
- Description: The report claims NIST SP 800-81 alignment after Rev. 3 publication but cites only Rev. 2 as the active framework, does not provide a legacy baseline justification, and omits evidence source dates.
