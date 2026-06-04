# Windows Process and PowerShell Evidence Fixtures

These fixtures exercise log-analysis v1.1.0 Windows command-line and PowerShell evidence gates. They distinguish process-name-only visibility gaps from corroborated command/script evidence.

---

## Vulnerable Fixture 1: 4688 Without Command Line Treated as High Confidence

### Evidence

- Event ID 4688 exists for `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
- `Process Command Line` is missing.
- Audit Process Creation state is unknown.
- Include command line in process creation events is unknown.
- Host role is a management jump box with scheduled administrative automation.
- The report labels the event "high-confidence malicious PowerShell execution" based only on process name and parent process.

### Expected Result

- Flag `LOG-WINPROC-01`.
- Flag `LOG-WINPROC-02`.
- Add a visibility gap for missing command-line collection state.
- Downgrade confidence until command-line, script block, Sysmon, EDR, network, file, or baseline evidence corroborates the process event.

---

## Vulnerable Fixture 2: EncodedCommand Without Script Block Correlation

### Evidence

- Event ID 4688 shows `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA...`.
- No Microsoft-Windows-PowerShell/Operational Event ID 4104 records were collected.
- Script Block Logging policy state is unknown.
- No ScriptBlockText, ScriptBlockId, or runspace/session correlation is available.
- The report claims the decoded payload executed but does not show decoded script evidence.

### Expected Result

- Flag `LOG-PWSH-01`.
- Record missing 4104 or equivalent script-content telemetry as a visibility gap.
- Treat the encoded command line as suspicious process evidence, not proof of script contents.

---

## Vulnerable Fixture 3: ScriptBlockText Reported Without Redaction

### Evidence

- Event ID 4104 contains `ScriptBlockText` with a bearer token and internal URL query string.
- The finding quotes the full token and URL.
- Protected Event Logging state is unknown.
- No collector-side masking or report redaction is documented.

### Expected Result

- Flag `LOG-PWSH-03`.
- Redact the token and private URL details before reporting.
- Record protected logging or collector-side controls as missing or unknown.

---

## Benign Fixture 1: Management Automation With Complete Evidence

### Evidence

- Event ID 4688 includes the full command line for a signed administrative maintenance script.
- Audit Process Creation and Include command line in process creation events are both enabled.
- Event ID 4104 contains matching ScriptBlockText and ScriptBlockId for the same user, host, and time window.
- Change ticket and scheduled task metadata match the execution time.
- Sensitive command-line values are redacted in the report.

### Expected Result

- Do not flag `LOG-WINPROC-01`, `LOG-WINPROC-02`, `LOG-PWSH-01`, or `LOG-PWSH-03`.
- Classify as benign or low priority if the activity matches baseline and change evidence.

---

## Benign Fixture 2: Sysmon and EDR Corroborate Process Context

### Evidence

- Windows Security 4688 lacks the command-line field.
- Sysmon Event ID 1 and EDR process telemetry both show the command line, parent process, signer, hash, and process tree.
- The EDR collector coverage is verified for the host group.
- No suspicious network, file write, or credential-access activity follows the process.

### Expected Result

- Do not treat missing 4688 command line as complete native Windows evidence.
- Record Sysmon/EDR as corroborating telemetry after verifying collection state.
- Confidence may increase based on the corroborating sources, but the 4688 command-line gap remains documented.

---

## Benign Fixture 3: PowerShell 7 on Linux With Named Channel

### Evidence

- The process is `pwsh` on Linux.
- PowerShell logs are collected from journald and forwarded to syslog.
- The report names the platform, collector, and PowerShell version.
- Script block logging is enabled through `powershell.config.json`.
- Sensitive script content is redacted before central reporting.

### Expected Result

- Do not flag `LOG-PWSH-02`.
- Do not assume Windows PowerShell 5.1 event-channel names for this host.
- Treat the evidence as usable only after the Linux collector path and script block configuration are documented.
