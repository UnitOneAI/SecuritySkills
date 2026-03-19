# OWASP Top 10 Detection Patterns (Grep Regex)

## A01:2021 -- Broken Access Control

```
# IDOR — direct use of user-supplied ID in DB query without ownership check
params\.id|req\.params|request\.args\.get.*id
# Missing CSRF protection
csrf.*disable|csrf.*false|@csrf_exempt
# Permissive CORS
Access-Control-Allow-Origin.*\*|cors\(\{.*origin.*true
# Path traversal indicators
\.\.\/|\.\.\\|path\.join.*req\.|sendFile.*req\.
```

## A02:2021 -- Cryptographic Failures

```
# Weak hashing
md5|sha1|DES|RC4|ECB
# Hard-coded secrets
password\s*=\s*["']|secret\s*=\s*["']|api_key\s*=\s*["']|private_key\s*=\s*["']
# Insecure random
Math\.random|random\.random|rand\(\)
# Missing TLS
http:\/\/.*api|http:\/\/.*login|secure\s*:\s*false
```

## A03:2021 -- Injection

```
# SQL injection
execute\(.*%s|execute\(.*\+|query\(.*\+|\.raw\(|\.rawQuery\(|\$\{.*\}.*SELECT|\.format\(.*SELECT
# OS command injection
exec\(|system\(|popen\(|child_process|shell=True|Runtime\.getRuntime\(\)\.exec
# XSS / template injection
innerHTML|\.html\(|dangerouslySetInnerHTML|v-html|\|safe|\|raw|render_template_string
# NoSQL injection
\$where|\$gt|\$ne|\$regex.*req\.|find\(.*req\.
# Header injection
setHeader\(.*req\.|res\.set\(.*req\.|response\.addHeader.*request\.getParameter
```

## A04:2021 -- Insecure Design

```
# Client-side-only validation
# (Look for validation logic only in frontend files, absent from backend handlers)
# Rate limiting absent
rateLimit|rate_limit|throttle|slowDown
# Account enumeration
"user not found"|"email not found"|"no account"|"invalid email"
# Missing lockout
failedAttempts|failed_attempts|lockout|max_attempts
```

## A05:2021 -- Security Misconfiguration

```
# Debug mode
DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV.*development
# XXE
DocumentBuilderFactory|SAXParser|XMLReader|etree\.parse|lxml.*parse
# Missing security headers
X-Content-Type-Options|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security
# Default credentials
admin.*admin|password.*password|default.*key|changeme|TODO.*password
# Verbose errors
stack.*trace|stackTrace|detailed.*error|showErrors\s*:\s*true
```

## A06:2021 -- Vulnerable and Outdated Components

```
# Dependency files to inspect
package\.json|requirements\.txt|Pipfile|Gemfile|pom\.xml|build\.gradle|go\.mod|composer\.json
# Lock files (verify existence)
package-lock\.json|yarn\.lock|Pipfile\.lock|Gemfile\.lock|composer\.lock
# Deprecated libraries (examples)
angular\.js|jquery\s*["\'].*1\.|lodash.*3\.|moment\(\)|request\(  # (npm 'request' is deprecated)
```

## A07:2021 -- Identification and Authentication Failures

```
# Session management
session\.id|sessionId|JSESSIONID|connect\.sid|session_token
# Weak password policy
minLength.*[0-5]|passwordMinLength|min_password_length
# Session in URL
session.*=.*req\.query|token.*=.*req\.query|url.*session
# Missing session rotation
regenerate|rotateSession|session\.create|session_regenerate_id
# Certificate validation bypass
rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CERT_NONE|InsecureRequestWarning.*disable
```

## A08:2021 -- Software and Data Integrity Failures

```
# Insecure deserialization
ObjectInputStream|readObject\(|pickle\.load|yaml\.load|yaml\.unsafe_load|unserialize\(|Marshal\.load|BinaryFormatter|JsonConvert\.DeserializeObject.*TypeNameHandling
# Missing SRI
<script.*src=.*cdn|<link.*href=.*cdn|integrity=
# CI/CD integrity
curl.*\|.*sh|curl.*\|.*bash|wget.*\|.*sh|pip install.*--trusted-host
```

## A09:2021 -- Security Logging and Monitoring Failures

```
# Logging presence
logger\.|log\.|console\.log|logging\.|Log\.|syslog|winston|bunyan|pino|log4j|NLog|Serilog
# Sensitive data in logs
log.*password|log.*token|log.*secret|log.*credit_card|log.*ssn|logger.*api_key
# Log injection
log.*req\.body|log.*request\.getParameter|logger\.info\(.*\+.*req
```

## A10:2021 -- Server-Side Request Forgery (SSRF)

```
# HTTP client calls with user input
requests\.get\(|requests\.post\(|urllib\.request|http\.get\(|fetch\(|axios\(|HttpClient|WebClient|curl_exec
# URL parameters
url=|dest=|redirect=|uri=|callback=|src=.*http
# Cloud metadata (hardcoded blocking check)
169\.254\.169\.254|metadata\.google|metadata\.azure
```
