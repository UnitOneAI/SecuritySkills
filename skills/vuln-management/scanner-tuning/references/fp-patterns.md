# False Positive Pattern Table

Extracted from the scanner-tuning SKILL.md.

| Pattern | Description | Identification Method | CWE Example |
|---|---|---|---|
| **Version-based detection without validation** | Scanner detects a vulnerable version string but the specific vulnerable code/feature is not present | Compare detected version against actual installed version; verify patch status via package manager | CWE-693 misidentified |
| **Banner-based detection** | Scanner reads a service banner that reports an outdated version, but the software has been patched without updating the banner | Verify actual version via authenticated check; compare banner vs. binary version | CWE-200 false trigger |
| **Protocol-level detection without exploit validation** | Scanner flags a protocol vulnerability but the specific cipher suite or configuration is not actually in use | Review actual TLS configuration; compare against scanner finding | CWE-326 false match |
| **OS/platform misidentification** | Scanner misidentifies the target OS or platform, leading to inapplicable plugin results | Verify OS fingerprint; compare scanner-detected OS against actual OS | N/A -- detection error |
| **Inherited/container base image findings** | Scanner detects vulnerabilities in a container base image layer that are overridden or not reachable in the final image | Analyze Dockerfile layer order; verify whether vulnerable files exist in the final image | Context-dependent |
| **Informational findings elevated to vulnerability** | Scanner reports an informational check with a severity rating that implies vulnerability | Review plugin/check documentation; confirm whether the finding indicates an actual exploitable weakness | N/A -- severity error |
| **Compensated vulnerability** | A real vulnerability exists but a compensating control renders it unexploitable in the deployment context | Document compensating control; this is risk acceptance, not a false positive -- track separately | Context-dependent |
