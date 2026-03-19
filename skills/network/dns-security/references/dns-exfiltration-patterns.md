# DNS Exfiltration Patterns

Extracted from the dns-security SKILL.md.

## Exfiltration Indicators

| Indicator | Normal | Suspicious | Detection Method |
|-----------|--------|-----------|-----------------|
| **Query name length** | < 30 chars | > 50 chars, near 253-char max | Monitor average FQDN length per source |
| **Subdomain label count** | 2-4 labels | > 6 labels | Count label depth |
| **Label entropy** | Low (readable words) | High (base32/base64 encoded) | Shannon entropy > 3.5 per label |
| **Query type distribution** | A, AAAA dominant | Heavy TXT, NULL, CNAME | Monitor query type ratios |
| **Query volume per domain** | < 100/hr to a single domain | > 1000/hr to single obscure domain | Volumetric per-domain threshold |
| **Response size** | < 512 bytes | TXT responses > 512 bytes, multiple TXT records | Monitor response payload sizes |

## Tunneling Tool Signatures

### iodine
- Uses NULL or TXT queries with base128 encoding
- Pattern: long encoded labels to a dedicated domain
- Example: `<base128-encoded-data>.t.example.com NULL`

### dnscat2
- Uses CNAME, TXT, or MX with hex encoding
- Pattern: hex strings as subdomain labels
- Example: `abcdef0123456789.dnscat.example.com TXT`

### dns2tcp
- Uses KEY or TXT queries
- Pattern: sequential numbered labels
- Example: `0001.<encoded>.d.example.com KEY`

## Detection Configuration

Deploy detection at:
- **Recursive resolver logging:** Enable query logging with source IP, query name, query type, response code, response size
- **Network flow data:** Monitor DNS (UDP/TCP 53) volume per source IP
- **SIEM correlation rules:**
  - Alert on > N queries to a single domain within a time window from a single source
  - Alert on average query name length exceeding threshold per source
  - Alert on high ratio of TXT/NULL queries from a single source
  - Alert on queries to domains with > 5 subdomain labels
