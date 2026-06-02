# Vulnerable: Stale Threat Intelligence Overconfidence

```text
Alert: Outbound connection to rare ASN
Threat intel lookup: no match
Feed status: last updated 17 days ago
Network logs: current
EDR telemetry: current
Analyst note: negative TI means destination is clean
Incorrect disposition: False Positive
```

Expected handling:

- Negative threat-intelligence evidence should be downgraded because feed
  freshness is stale.
- The report should record lookup time, feed age, and confidence impact.
- Classification should rely on current network and endpoint behavior rather
  than treating the stale negative lookup as proof of benign activity.

