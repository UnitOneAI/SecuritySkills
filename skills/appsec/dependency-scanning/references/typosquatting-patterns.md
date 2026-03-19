# Typosquatting Detection Patterns

## What Is Typosquatting

Typosquatting (also called dependency confusion or combosquatting) is a supply chain attack where a malicious package is published with a name similar to a popular legitimate package, hoping developers will install it by mistake.

## Common Patterns

| Pattern | Legitimate | Typosquat Example |
|---|---|---|
| Character swap | `requests` | `reqeusts`, `requets` |
| Hyphen/underscore confusion | `python-dateutil` | `python_dateutil` (may or may not be malicious; verify publisher) |
| Scope/namespace omission | `@angular/core` | `angular-core` (unscoped) |
| Prefix/suffix addition | `lodash` | `lodash-utils`, `lodash-js` |
| Combosquatting | `colors` | `colors2`, `node-colors` |
| Namespace confusion | Internal package `@company/auth` | Public `company-auth` on npm (dependency confusion) |

## Detection Approach

1. **Manifest review**: For each declared dependency, verify the package name against the canonical registry listing (npmjs.com, pypi.org, crates.io, pkg.go.dev).
2. **Publisher verification**: Check that the package publisher/maintainer matches known trusted entities. Look for verified publisher badges where available.
3. **Download count anomalies**: A package with a similar name to a popular one but very low download counts is suspicious.
4. **Recency check**: Packages created very recently that shadow established package names warrant extra scrutiny.
5. **Install script inspection**: In npm, review `preinstall`/`postinstall` scripts. Malicious typosquat packages frequently use install hooks to exfiltrate environment variables or credentials.

## Mitigation

- Use scoped packages where possible (`@org/package`).
- Configure `.npmrc` or pip index settings to point to a private registry with an allow-list for public packages.
- Implement dependency confusion protections: claim your internal package names on public registries, or use registry proxy tools like Artifactory or Nexus with routing rules.
- Run `socket.dev`, `npm audit signatures`, or `sigstore` verification to validate package provenance.
