# Sysmon Event ID Reference

Extracted from the log-analysis SKILL.md.

| Sysmon EID | Description | Security Use |
|------------|-------------|-------------|
| **1** | Process creation | Full command line, parent process, hashes -- primary detection source |
| **3** | Network connection | Outbound connections with process context -- C2 detection |
| **7** | Image loaded | DLL loading -- detect DLL side-loading, injection |
| **8** | CreateRemoteThread | Thread injection into another process -- code injection detection |
| **10** | ProcessAccess | Process accessing another process -- credential dumping (LSASS access) |
| **11** | FileCreate | File creation with full path -- malware dropping, staging |
| **12/13/14** | Registry events | Registry create, set value, rename -- persistence detection |
| **15** | FileCreateStreamHash | Alternate data stream creation -- hiding data |
| **22** | DNSEvent | DNS queries with process context -- C2 domain resolution |
| **23** | FileDelete | File deletion with archiving -- anti-forensics detection |
| **25** | ProcessTampering | Process image change -- process hollowing/herpaderping |
