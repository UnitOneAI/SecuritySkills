# Linux Authentication Log Patterns

Extracted from the log-analysis SKILL.md.

## Key Patterns

| Pattern | Indicates | ATT&CK Mapping |
|---------|-----------|-----------------|
| Multiple `Failed password` from same source IP | Brute force attack | T1110 |
| `Failed password for invalid user` | Username enumeration or spray | T1110.003 |
| `Accepted password` from unusual IP or at unusual time | Potential compromised credentials | T1078 |
| `sudo` command to sensitive files (/etc/shadow, /etc/passwd) | Credential access or reconnaissance | T1003.008 |
| `useradd` or `usermod` outside change management | Persistence via new account | T1136.001 |
| `su` to root from non-admin user | Privilege escalation attempt | T1548 |
| `session opened for user root by (uid=XXX)` where XXX is non-zero | Privilege escalation success | T1548 |
| `sshd.*Did not receive identification string` | Port scanning or reconnaissance | T1046 |

## Log File Locations

- Debian/Ubuntu: `/var/log/auth.log`
- RHEL/CentOS: `/var/log/secure`
