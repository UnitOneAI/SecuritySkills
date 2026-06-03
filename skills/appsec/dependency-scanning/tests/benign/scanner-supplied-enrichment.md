# Benign: scanner-supplied enrichment with source dates

This fixture calibrates accepted offline evidence. The reviewer can use
scanner-supplied EPSS/KEV enrichment if the scanner output records the source,
scanner version, and feed dates.

```json
{
  "scanner": "example-scanner",
  "scannerVersion": "2.4.0",
  "generatedAt": "2026-06-03T08:00:00Z",
  "vulnerabilities": [
    {
      "id": "CVE-2026-12345",
      "package": "example-lib",
      "installedVersion": "1.2.3",
      "fixedVersion": "1.2.4",
      "cvss": 9.1,
      "epss": {
        "score": 0.42,
        "source": "FIRST EPSS",
        "date": "2026-06-03"
      },
      "kev": {
        "listed": true,
        "source": "CISA KEV",
        "feedDate": "2026-06-03",
        "dueDate": "2026-06-24",
        "requiredAction": "Apply updates per vendor instructions",
        "knownRansomwareCampaignUse": "Unknown"
      }
    }
  ]
}
```

## Expected review result

- Enrichment source: `scanner-supplied`.
- EPSS date, KEV feed date, due date, and required action are retained in the
  vulnerability finding.
- Priority remains urgent because KEV and high EPSS are both present.
