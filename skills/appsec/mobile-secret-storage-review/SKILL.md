---
name: mobile-secret-storage-review
description: >
  Reviews Android and iOS applications for insecure local secret storage,
  including plaintext tokens in preferences, weak Keychain/Keystore usage,
  backup leakage, logs, screenshots, debug-build drift, biometric gates, and
  token lifecycle handling. Use when reviewing mobile app code, threat models,
  or incident reports involving persisted credentials, refresh tokens, API keys,
  device-bound secrets, or offline session material.
tags: [appsec, mobile, secrets, storage]
role: [appsec-engineer, security-engineer]
phase: [build, review, operate]
frameworks: [OWASP-MASVS, OWASP-MSTG, CWE-312, CWE-922]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[mobile-app-source-or-change]"
---

# Mobile Secret Storage Review

A structured process for reviewing Android and iOS applications that persist
tokens, API keys, certificates, device credentials, or other local secrets. The
skill focuses on whether mobile secrets are stored in platform-backed controls,
excluded from unsafe backup/sync paths, protected from debug artifacts, and
cleared or rotated when the user logs out or compromise is suspected.

**Privacy rule:** Do not print, copy, or retain real secret values during the
review. Report secret type, storage path, and risk evidence with redacted values
only.

---

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Use this skill for:

- Android/Kotlin or Android/Java reviews involving `SharedPreferences`,
  `DataStore`, Room/SQLite, files, caches, `EncryptedSharedPreferences`,
  Android Keystore, or backup settings.
- iOS/Swift or Objective-C reviews involving `UserDefaults`, files,
  CoreData/SQLite, Keychain Services, `NSFileProtection`, pasteboard, or
  screenshot/logging controls.
- Hybrid mobile stacks such as React Native, Flutter, Capacitor, or Cordova
  when they bridge into native secret storage.
- Incident reviews involving exposed refresh tokens, offline session material,
  mobile logs, debug builds, or device backups.

Do not use this skill for server-side vault architecture or CI credential
rotation unless the mobile application is the primary trust boundary. Use
`secrets-management` for repository-wide secret detection and vault posture.

---

## Step 1: Scope Local Secret Material

Identify every secret-like value the app creates, receives, caches, or persists.

### 1.1 Inventory Questions

| Question | Evidence to Collect |
|---|---|
| What secret types are present? | access tokens, refresh tokens, API keys, client certificates, private keys, device binding keys, recovery codes |
| Where can the secret be written? | preferences, files, SQLite/Room/CoreData, Keychain/Keystore, clipboard, logs, screenshots, crash reports, analytics |
| How long should it live? | session only, offline window, refresh-token lifetime, device registration lifetime |
| What trust boundary protects it? | OS key store, hardware-backed key, biometric gate, app sandbox, server-side revocation |
| What clears or rotates it? | logout, password reset, device loss, suspected compromise, token refresh failure |

### 1.2 Search Patterns

Use these searches to map storage and leakage paths.

```text
# Android local persistence
SharedPreferences
getSharedPreferences
PreferenceManager
DataStore
RoomDatabase
SQLiteOpenHelper
openFileOutput
getFilesDir
getExternalFilesDir
cacheDir
EncryptedSharedPreferences
MasterKey
KeyGenParameterSpec
setUserAuthenticationRequired
android:allowBackup
dataExtractionRules
fullBackupContent
Log.
Timber.
FLAG_SECURE

# iOS local persistence
UserDefaults
NSUbiquitousKeyValueStore
FileManager
NSFileProtection
SecItemAdd
SecItemUpdate
SecAccessControl
kSecAttrAccessible
kSecAttrAccessControl
LAContext
UIPasteboard
print(
NSLog
isProtectedDataAvailable
applicationWillResignActive
```

> **Gate MSS-01:** Do not issue findings until the review identifies the secret
> type, storage path, intended lifetime, and logout/rotation owner for each
> sensitive value in scope.

---

## Step 2: Classify Storage Risk

Classify each persisted value by sensitivity and attacker model.

| Class | Examples | Minimum Expected Control |
|---|---|---|
| Critical | refresh tokens, private keys, long-lived device credentials | platform Keychain/Keystore with restrictive accessibility and revocation path |
| High | access tokens, session cookies, short-lived OAuth tokens | platform-backed storage or encrypted preferences using non-exportable keys |
| Medium | device identifiers tied to auth state, CSRF/session hints | app-private storage with backup exclusion and lifecycle cleanup |
| Low | non-sensitive feature flags, cached display preferences | normal app storage acceptable if not mixed with secrets |

Treat "short-lived" as unproven until the code or auth contract shows an expiry,
refresh, and revocation path. A token in plaintext is still a finding if the
compromise window is meaningful.

---

## Step 3: Android Review Gates

### MSS-02A: Reject Plaintext Token Persistence

Flag Critical or High secrets stored with these patterns:

```kotlin
// VULNERABLE: refresh token stored as plaintext app preference
prefs.edit().putString("refresh_token", token).apply()
```

```kotlin
// VULNERABLE: token copied into app file without platform-backed key protection
File(context.filesDir, "session.json").writeText("""{"token":"$token"}""")
```

Acceptable storage should use Android Keystore-backed keys, preferably hardware
backing where available:

```kotlin
// BETTER: encrypted preferences backed by a MasterKey in Android Keystore
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_session",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
)
securePrefs.edit().putString("refresh_token", redactedToken).apply()
```

Review the generated `KeyGenParameterSpec` when present:

- `setUserAuthenticationRequired(true)` for secrets that should be biometric or
  device-unlock gated.
- StrongBox or hardware-backed protection where supported and required by the
  risk model.
- No exportable raw key material committed, logged, or derived from constants.
- No custom encryption with hardcoded keys, predictable IVs, ECB mode, or
  silently ignored crypto failures.

### MSS-03A: Android Backup and Sync Exposure

Inspect `AndroidManifest.xml`, `res/xml/data_extraction_rules.xml`, and
`res/xml/backup_rules.xml`.

Flag High risk when secret-bearing stores are included in Auto Backup, cloud
restore, device transfer, or external storage.

Controls to verify:

- `android:allowBackup="false"` for apps that persist high-value secrets without
  explicit exclusion rules.
- Secret preference files and databases are excluded from `cloud-backup` and
  `device-transfer`.
- No secret material is stored in external storage or shared cache directories.
- Restored sessions are revalidated server-side before use.

---

## Step 4: iOS Review Gates

### MSS-02B: Require Keychain for Long-Lived Secrets

Flag Critical or High secrets stored in `UserDefaults`, app files, CoreData, or
SQLite without Keychain-backed protection:

```swift
// VULNERABLE: refresh token persists in iCloud-restorable defaults
UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
```

Prefer Keychain Services with restrictive accessibility:

```swift
// BETTER: Keychain item scoped to unlocked device and not migrated in backups
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.mobile.session",
    kSecAttrAccount as String: "refresh-token",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: tokenData
]
SecItemAdd(query as CFDictionary, nil)
```

Controls to verify:

- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or a stricter class is used for
  non-migratable secrets.
- Biometric-gated secrets use `SecAccessControl` and `LAContext` deliberately,
  with a fallback policy approved by product/security.
- No Keychain item uses broad accessibility such as
  `kSecAttrAccessibleAlways` for session material.
- File-based caches use `NSFileProtectionComplete` or an equivalent data
  protection class when storing sensitive-but-not-secret data.

### MSS-03B: iOS Backup, Sync, and Snapshot Exposure

Flag High risk when secrets can move through iCloud backup, app group containers,
pasteboard, screenshots, crash reports, or analytics.

Controls to verify:

- Keychain items that must not migrate use `ThisDeviceOnly`.
- Files containing sensitive data are marked with backup exclusion attributes.
- App switcher snapshots hide or blur secret-bearing screens.
- `UIPasteboard` use is avoided for tokens or explicitly cleared.
- Crash and analytics payloads redact token-bearing fields.

---

## Step 5: Debug Artifact and Runtime Leakage Review

### MSS-04: Logs, Screenshots, Clipboard, and Analytics

Search debug and telemetry paths for token-bearing values.

Flag findings when:

- `Log.d`, `Timber.d`, `print`, `NSLog`, crash metadata, analytics events, or
  support bundles include access tokens, refresh tokens, authorization headers,
  cookies, private keys, or decrypted payloads.
- `Authorization`, `Set-Cookie`, OAuth responses, or token refresh responses are
  logged without redaction.
- Secret-bearing screens can appear in Android screenshots/app switcher without
  `FLAG_SECURE` or equivalent masking where the risk model requires it.
- Clipboard or share-sheet flows expose tokens or recovery codes without
  expiration and user-visible warning.

Accepted evidence includes redacted log examples, unit tests for redaction, crash
payload schemas, and screenshot-masking code paths.

### MSS-05: Debug-Build Drift

Compare release and debug build behavior. A secure release build can still fail
if debug or QA builds are distributed with weaker storage.

Verify:

- Debug feature flags do not bypass Keychain/Keystore storage for real accounts.
- QA/staging builds cannot be used against production tokens unless they enforce
  the same local storage controls.
- Test fixtures and local mock credentials cannot leak into production bundles.
- Build variants do not enable verbose token logging by default.

---

## Step 6: Token Lifecycle and Compromise Handling

### MSS-06: Logout, Rotation, and Server-Side Revocation

For every locally persisted token, verify the lifecycle.

| Event | Required Evidence |
|---|---|
| Logout | local token deleted, memory copy cleared where practical, server session revoked if supported |
| Token refresh failure | stale refresh token removed and user reauth required |
| Password reset or account recovery | server invalidates old refresh tokens and clients recover safely |
| Device lost or compromised | user/admin can revoke device or session remotely |
| App reinstall/restore | restored state is revalidated and cannot silently resurrect an old session |

Flag High risk when local deletion is implemented but server-side revocation is
missing for long-lived refresh tokens. Flag Medium risk when revocation exists but
client-side cleanup is incomplete or untested.

---

## Finding Classification

| Severity | Criteria |
|---|---|
| Critical | Long-lived credential, refresh token, private key, or device credential stored plaintext or backup-restorable with realistic extraction path |
| High | Access token or session material stored outside platform-backed controls, included in backup/sync, or logged to telemetry |
| Medium | Secret-adjacent state lacks cleanup, screenshot masking, debug parity, or backup exclusion evidence |
| Low | Documentation, test, or monitoring gap where implementation appears safe but evidence is incomplete |

Do not inflate severity for non-secret preferences. Do not downgrade a finding
solely because the app sandbox exists; mobile threat models include backups,
device compromise, debug builds, support bundles, and rooted/jailbroken devices.

---

## Report Template

```markdown
## Mobile Secret Storage Review

### Scope
- Platforms:
- App modules:
- Secret types reviewed:
- Build variants reviewed:

### Storage Map
| Secret type | Platform | Storage path | Lifetime | Protection | Backup/sync status | Owner |
|---|---|---|---|---|---|---|

### Findings
1. **[Severity] MSS-XX: Finding title**
   - Evidence:
   - Impact:
   - Frameworks: OWASP MASVS, CWE-312/CWE-922
   - Remediation:
   - Validation:

### Positive Controls
- Platform-backed storage:
- Backup exclusions:
- Redaction controls:
- Logout/revocation controls:

### Follow-Up Tests
- Add regression tests for:
- Manual device validation needed:
```

---

## Review Checklist

- [ ] MSS-01 storage map covers every secret-like value in scope.
- [ ] Critical and High secrets are not stored in plaintext preferences, files,
      SQLite/CoreData, or external storage.
- [ ] Android Keystore or iOS Keychain controls match the secret lifetime and
      attacker model.
- [ ] Android Auto Backup, device transfer, iCloud backup, and app group paths
      exclude secret-bearing stores.
- [ ] Logs, crash reports, analytics, screenshots, clipboard, and support
      bundles redact or avoid secret material.
- [ ] Debug, QA, and release builds enforce equivalent storage protections for
      production credentials.
- [ ] Logout, refresh failure, password reset, account recovery, and compromise
      workflows delete and revoke tokens appropriately.
- [ ] Findings contain redacted evidence only and include validation steps.
