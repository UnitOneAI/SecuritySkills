# Benign: converted rule includes positive and benign fixtures

This sample should not be reported for missing regression coverage. The conversion notes include a malicious event that should alert, a benign event that should not alert, and the mapped field names used after parser normalization.

```yaml
rule: suspicious-rundll32-child-process
source_platform: windows-securityevent
target_platform: mde-deviceprocessevents
field_map:
  Account: InitiatingProcessAccountName
  Computer: DeviceName
  Process: FileName
fixtures:
  should_alert:
    FileName: rundll32.exe
    InitiatingProcessAccountName: alice@example.com
    DeviceName: workstation-22
    ProcessCommandLine: rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"
  should_not_alert:
    FileName: rundll32.exe
    InitiatingProcessAccountName: patch-admin@example.com
    DeviceName: patch-host-01
    ProcessCommandLine: rundll32.exe shell32.dll,Control_RunDLL
```

Expected result:

- No finding for missing conversion fixtures.
- Reviewer should still inspect whether the fixture values match the production parser and rule syntax.
