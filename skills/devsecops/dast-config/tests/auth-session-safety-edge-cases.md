# DAST Authenticated Session Safety Edge Cases

Use these calibration cases when reviewing authenticated DAST configuration.

## Vulnerable: stale copied tokens and logout in scope

```yaml
env:
  contexts:
    - name: app
      urls:
        - https://staging.example.com
      includePaths:
        - https://staging.example.com/.*
      authentication:
        method: header
        parameters:
          - header: Cookie
            value: session=eyJstaleCopiedCookie; csrf=static-token-from-browser
jobs:
  - type: spider
  - type: activeScan
    parameters:
      scanOnlyInScope: true
```

Expected review outcome:

- Fail: copied session and CSRF values are static and will expire or misrepresent authenticated coverage.
- Fail: no logged-in/logged-out verification during spider and active-scan phases.
- Fail: logout, account deletion, password reset, and other state-changing routes are not excluded.
- Partial: target is staging, but there is no cleanup or state reset evidence.

## Benign: browser auth with session verification and state reset

```yaml
env:
  contexts:
    - name: app
      urls:
        - https://staging.example.com
      includePaths:
        - https://staging.example.com/.*
      excludePaths:
        - https://staging.example.com/logout.*
        - https://staging.example.com/account/delete.*
        - https://staging.example.com/admin/reset.*
      authentication:
        method: browser
        parameters:
          loginPageUrl: https://staging.example.com/login
          loginPageWait: 5
        verification:
          method: response
          loggedInRegex: "\\Qdata-user-id=\\E"
          loggedOutRegex: "\\QSign in\\E"
          pollFrequency: 25
          pollUnits: requests
      users:
        - name: standard-user
          credentials:
            username: ${DAST_STANDARD_USERNAME}
            password: ${DAST_STANDARD_PASSWORD}
jobs:
  - type: spider
    parameters:
      maxDuration: 5
  - type: activeScan
    parameters:
      scanOnlyInScope: true
      maxScanDurationInMins: 30
  - type: requestor
    parameters:
      user: standard-user
      requestsFile: zap-authenticated-smoke.yaml
  - type: report
```

Expected review outcome:

- Pass: browser authentication can collect fresh CSRF, cookie, and hidden-field state.
- Pass: logged-in and logged-out indicators are phase-verifiable.
- Pass: destructive and logout paths are excluded.
- Needs evidence: final report should include authenticated URL count, anonymous URL count, and cleanup or snapshot-restore proof.
