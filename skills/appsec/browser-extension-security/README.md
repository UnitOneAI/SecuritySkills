# Browser Extension Security Review

This skill reviews Chrome Manifest V3 and Mozilla WebExtensions for practical security failures that general web and API reviews often miss:

- overbroad host and browser API permissions.
- unvalidated message passing between content scripts, background workers, extension pages, external pages, and native hosts.
- unsafe DOM rendering or dynamic code execution inside privileged extension contexts.
- sensitive token or secret storage in extension-local storage.
- excessive web-accessible resources and external-connectable exposure.

The review is intentionally centred on trust boundaries. A browser extension can sit between arbitrary web pages and privileged browser APIs, so a small sender-validation mistake can become cross-origin data access, tab injection, cookie exposure, or native-host abuse.

## Expected Output

The skill produces a structured report with extension inventory, high-risk permissions, message surfaces, sensitive data locations, and findings mapped to CWE. It must distinguish broad-but-justified permissions from unjustified default access.

## Test Coverage

The `tests/` directory includes three vulnerable examples and three benign examples:

- `vulnerable/broad-permissions.json`
- `vulnerable/unsafe-message-handler.js`
- `vulnerable/unsafe-content-script.js`
- `benign/scoped-permissions.json`
- `benign/validated-message-handler.js`
- `benign/safe-content-rendering.js`

Vulnerable examples should produce findings. Benign examples should not produce high or medium findings.

## References

- Chrome Extensions documentation, permissions and host permissions.
- Chrome Extensions documentation, Manifest V3 and `chrome.scripting`.
- Mozilla WebExtensions documentation, permissions and match patterns.
- CWE-79, Improper Neutralization of Input During Web Page Generation.
- CWE-94, Improper Control of Generation of Code.
- CWE-200, Exposure of Sensitive Information to an Unauthorized Actor.
- CWE-284, Improper Access Control.
- CWE-862, Missing Authorization.
- CWE-922, Insecure Storage of Sensitive Information.
