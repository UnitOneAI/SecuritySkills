## DNS Security Assessment Report

### Scope
- DNS infrastructure reviewed: public authoritative zones, internal recursive resolvers, enterprise protective DNS
- Configuration files analyzed: `dns/named.conf`, `dns/unbound.conf`, `mdm/dns-policy.json`
- Date: 2026-06-03
- Frameworks applied: NIST SP 800-81 Rev. 3, CIS Controls v8 (9.2)
- NIST publication source: https://csrc.nist.gov/pubs/sp/800/81/r3/final
- Assessment mode: Current baseline
- Legacy baseline justification: N/A

### DNSSEC Status

| Zone | Signed | Algorithm | Key Sizes | DS in Parent | Denial-of-Existence | Evidence Date | Status |
|------|--------|-----------|-----------|--------------|---------------------|---------------|--------|
| example.com | Yes | 13 | KSK:256/ZSK:256 | Yes | NSEC with local policy acceptance | 2026-06-02 | Pass |

### Resolver Security

| Resolver | DNSSEC Validation | Encrypted Transport | Protective DNS | Query Logging | Time Source | Evidence Date |
|----------|-------------------|--------------------|----------------|---------------|-------------|---------------|
| resolver-1 | Enabled | DoT to approved upstream | Yes | Yes | NTS-backed NTP | 2026-06-02 |

### Evidence Freshness

| Evidence Source | Source Date | Freshness Status | Notes |
|-----------------|-------------|------------------|-------|
| DNS config export | 2026-06-02 | Current | commit `abc1234` |
| Protective DNS feed | 2026-06-03 | Current | provider policy export |
| Resolver/client policy | 2026-06-02 | Current | MDM profile export |
| DNS logs/SIEM export | 2026-06-03 | Current | last 7 days |

### Expected Result

The report should not be flagged for stale NIST baseline use because it uses NIST SP 800-81 Rev. 3, records source dates, and does not cite Rev. 2 as current.
